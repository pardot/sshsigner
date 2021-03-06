// Code generated by go-swagger; DO NOT EDIT.

package signer

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/pardot/sshsigner/proto/sshsigner/v1alpha1/httpclient/models"
)

// NewSignHostKeyParams creates a new SignHostKeyParams object
// with the default values initialized.
func NewSignHostKeyParams() *SignHostKeyParams {
	var ()
	return &SignHostKeyParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewSignHostKeyParamsWithTimeout creates a new SignHostKeyParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewSignHostKeyParamsWithTimeout(timeout time.Duration) *SignHostKeyParams {
	var ()
	return &SignHostKeyParams{

		timeout: timeout,
	}
}

// NewSignHostKeyParamsWithContext creates a new SignHostKeyParams object
// with the default values initialized, and the ability to set a context for a request
func NewSignHostKeyParamsWithContext(ctx context.Context) *SignHostKeyParams {
	var ()
	return &SignHostKeyParams{

		Context: ctx,
	}
}

// NewSignHostKeyParamsWithHTTPClient creates a new SignHostKeyParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewSignHostKeyParamsWithHTTPClient(client *http.Client) *SignHostKeyParams {
	var ()
	return &SignHostKeyParams{
		HTTPClient: client,
	}
}

/*SignHostKeyParams contains all the parameters to send to the API endpoint
for the sign host key operation typically these are written to a http.Request
*/
type SignHostKeyParams struct {

	/*Body*/
	Body *models.V1alpha1SignHostKeyRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the sign host key params
func (o *SignHostKeyParams) WithTimeout(timeout time.Duration) *SignHostKeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the sign host key params
func (o *SignHostKeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the sign host key params
func (o *SignHostKeyParams) WithContext(ctx context.Context) *SignHostKeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the sign host key params
func (o *SignHostKeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the sign host key params
func (o *SignHostKeyParams) WithHTTPClient(client *http.Client) *SignHostKeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the sign host key params
func (o *SignHostKeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the sign host key params
func (o *SignHostKeyParams) WithBody(body *models.V1alpha1SignHostKeyRequest) *SignHostKeyParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the sign host key params
func (o *SignHostKeyParams) SetBody(body *models.V1alpha1SignHostKeyRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *SignHostKeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
