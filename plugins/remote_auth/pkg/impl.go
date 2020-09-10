package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	envoycorev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoyauthv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/solo-io/ext-auth-plugins/api"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"
	"io"
	"net/http"
	"reflect"
	"strings"
)

var (
	UnexpectedConfigError = func(typ interface{}) error {
		return errors.New(fmt.Sprintf("unexpected config type %T", typ))
	}
	_ api.ExtAuthPlugin = new(RemoteAuthPlugin)
)

type RemoteAuthPlugin struct{}

type Config struct {
	AuthUrl               string
	ForwardRequestHeaders []string
	ResponseHeaders       map[string]string
}

func (p *RemoteAuthPlugin) NewConfigInstance(ctx context.Context) (interface{}, error) {
	return &Config{}, nil
}

func (p *RemoteAuthPlugin) GetAuthService(ctx context.Context, configInstance interface{}) (api.AuthService, error) {
	config, ok := configInstance.(*Config)
	if !ok {
		return nil, UnexpectedConfigError(configInstance)
	}

	logger(ctx).Infow("Parsed RemoteAuthPlugin config",
		zap.Any("authUrl", config.AuthUrl),
		zap.Any("forwardRequestHeaders", config.ForwardRequestHeaders),
		zap.Any("responseHeaders", config.ResponseHeaders),
	)

	forwardHeadersMap := map[string]bool{}
	for _, v := range config.ForwardRequestHeaders {
		forwardHeadersMap[v] = true
	}

	attributesToHeaderMap := map[string]string{}
	for headerKey, attribute := range config.ResponseHeaders {
		attributesToHeaderMap[attribute] = headerKey
	}

	return &RemoteAuthService{
		httpClient:             &http.Client{},
		AuthUrl:                config.AuthUrl,
		ForwardRequestHeaders:  forwardHeadersMap,
		AttributesToHeadersMap: attributesToHeaderMap,
	}, nil
}

type RemoteAuthService struct {
	httpClient             *http.Client
	AuthUrl                string
	ForwardRequestHeaders  map[string]bool
	AttributesToHeadersMap map[string]string
}

func (c *RemoteAuthService) Start(context.Context) error {
	return nil
}

func (c *RemoteAuthService) Authorize(ctx context.Context, authzRequest *api.AuthorizationRequest) (*api.AuthorizationResponse, error) {
	request, err := http.NewRequestWithContext(ctx, "GET", c.AuthUrl, io.Reader(nil))
	if err != nil {
		return nil, err
	}

	c.forwardAllowedHeaders(request, authzRequest)
	response, err := c.httpClient.Do(request)
	if err != nil {
		logger(ctx).Errorw("Unexpected error from upstream", zap.Error(err))
		return nil, err
	}

	if response.StatusCode != 200 {
		logger(ctx).Infow("Unsuccessful response from upstream, denying access")
		return api.UnauthenticatedResponse(), nil
	}

	logger(ctx).Infow("Successful response from upstream, allowing request")
	responseHeaders, err := c.extractResponseHeaders(response.Body)
	if err != nil {
		logger(ctx).Errorw("Unexpected error while extracting response headers", zap.Error(err))
		return nil, err
	}

	authzRresponse := api.AuthorizedResponse()
	authzRresponse.CheckResponse.HttpResponse = &envoyauthv2.CheckResponse_OkResponse{
		OkResponse: &envoyauthv2.OkHttpResponse{
			Headers: responseHeaders,
		},
	}
	return authzRresponse, nil
}

func (c *RemoteAuthService) forwardAllowedHeaders(remoteRequest *http.Request, authzRequest *api.AuthorizationRequest) {
	for key, value := range authzRequest.CheckRequest.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		if v, ok := c.ForwardRequestHeaders[key]; ok && v {
			remoteRequest.Header.Add(key, value)
		}
	}
}

func (c *RemoteAuthService) extractResponseHeaders(authzBody io.ReadCloser) ([]*envoycorev2.HeaderValueOption, error) {
	var data map[string]interface{}
	if err := json.NewDecoder(authzBody).Decode(&data); err != nil {
		return nil, err
	}

	var headers []*envoycorev2.HeaderValueOption
	for attribute, header := range c.AttributesToHeadersMap {
		if raw, ok := data[attribute]; ok {
			if value := stringifyValue(raw); value != nil {
				headers = append(headers, &envoycorev2.HeaderValueOption{
					Header: &envoycorev2.HeaderValue{
						Key:   header,
						Value: *value,
					},
				})
			}
		}
	}

	return headers, nil
}

func stringifyValue(raw interface{}) *string {
	var value string
	v := reflect.ValueOf(raw)
	switch v.Kind() {
	case reflect.Bool:
		value = fmt.Sprintf("%v", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int32, reflect.Int64:
		value = fmt.Sprintf("%v", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint32, reflect.Uint64:
		value = fmt.Sprintf("%v", v.Uint())
	case reflect.Float32, reflect.Float64:
		value = fmt.Sprintf("%v", v.Float())
	case reflect.String:
		value = v.String()
	case reflect.Slice, reflect.Array:
		var arr []string
		for i := 0; i < v.Len(); i++ {
			if s := stringifyValue(v.Index(i).Interface()); s != nil {
				arr = append(arr, *s)
			}
		}
		value = strings.Join(arr, ",")
	default:
		return nil
	}
	return &value
}

func logger(ctx context.Context) *zap.SugaredLogger {
	return contextutils.LoggerFrom(contextutils.WithLogger(ctx, "remote_auth_plugin"))
}
