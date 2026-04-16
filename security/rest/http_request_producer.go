package rest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxhelper"
)

type httpRequestProducer struct {
	httpMethod         string
	url                string
	headers            map[string][]string
	bodyBytes          []byte
	authHeaderSupplier func(ctx context.Context) (string, error)
}

func newHttpRequestProducer(httpMethod, url string, headers map[string][]string, bodyReader io.Reader) (*httpRequestProducer, error) {
	bodyBytes, err := bodyReaderToBytes(bodyReader)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request producer: %w", err)
	}
	producer := &httpRequestProducer{httpMethod: httpMethod, url: url, headers: headers, bodyBytes: bodyBytes}
	return producer, nil
}

func bodyReaderToBytes(bodyReader io.Reader) ([]byte, error) {
	if bodyReader == nil {
		return nil, nil
	}

	bodyBytes, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}
	return bodyBytes, nil
}

func (producer *httpRequestProducer) getBody() io.Reader {
	if len(producer.bodyBytes) > 0 {
		return bytes.NewReader(producer.bodyBytes)
	}
	return nil
}

func (producer *httpRequestProducer) produce(ctx context.Context) (*http.Request, error) {
	httpRequest, err := http.NewRequest(producer.httpMethod, producer.url, producer.getBody())
	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}
	//context propagation part
	err = ctxhelper.AddSerializableContextData(ctx, httpRequest.Header.Add)
	if err != nil {
		return nil, fmt.Errorf("cannot add serializable data: %w", err)
	}
	authHeaderValue, err := producer.authHeaderSupplier(ctx)
	if err != nil {
		return nil, &TokenAcquisitionError{Err: err}
	}
	httpRequest.Header.Add("Authorization", authHeaderValue)
	for header, values := range producer.headers {
		for _, value := range values {
			httpRequest.Header.Add(header, value)
		}
	}
	return httpRequest, nil
}
