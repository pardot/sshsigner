// Code generated by go-swagger; DO NOT EDIT.

package signer

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new signer API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for signer API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	HostSigners(params *HostSignersParams) (*HostSignersOK, error)

	SignerSignHostKey(params *SignerSignHostKeyParams) (*SignerSignHostKeyOK, error)

	SignerSignUserKey(params *SignerSignUserKeyParams) (*SignerSignUserKeyOK, error)

	SignerUserSigners(params *SignerUserSignersParams) (*SignerUserSignersOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  HostSigners gets a list of currently valid signers for host keys
*/
func (a *Client) HostSigners(params *HostSignersParams) (*HostSignersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewHostSignersParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "HostSigners",
		Method:             "GET",
		PathPattern:        "/sshsigner/v1alpha1/hostsigners",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &HostSignersReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*HostSignersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*HostSignersDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
  SignerSignHostKey signs a host key
*/
func (a *Client) SignerSignHostKey(params *SignerSignHostKeyParams) (*SignerSignHostKeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSignerSignHostKeyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "Signer_SignHostKey",
		Method:             "POST",
		PathPattern:        "/sshsigner/v1alpha1/hostkey",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &SignerSignHostKeyReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SignerSignHostKeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*SignerSignHostKeyDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
  SignerSignUserKey signs a users key for access
*/
func (a *Client) SignerSignUserKey(params *SignerSignUserKeyParams) (*SignerSignUserKeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSignerSignUserKeyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "Signer_SignUserKey",
		Method:             "POST",
		PathPattern:        "/sshsigner/v1alpha1/userkey",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &SignerSignUserKeyReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SignerSignUserKeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*SignerSignUserKeyDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
  SignerUserSigners gets a list of currently valid signers for user keys
*/
func (a *Client) SignerUserSigners(params *SignerUserSignersParams) (*SignerUserSignersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSignerUserSignersParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "Signer_UserSigners",
		Method:             "GET",
		PathPattern:        "/sshsigner/v1alpha1/usersigners",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &SignerUserSignersReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SignerUserSignersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*SignerUserSignersDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}