// Code generated by go-swagger; DO NOT EDIT.

package signer

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/pardot/sshsigner/proto/sshsigner/v1alpha1/httpclient/models"
)

// SignerSignHostKeyReader is a Reader for the SignerSignHostKey structure.
type SignerSignHostKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SignerSignHostKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSignerSignHostKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSignerSignHostKeyDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSignerSignHostKeyOK creates a SignerSignHostKeyOK with default headers values
func NewSignerSignHostKeyOK() *SignerSignHostKeyOK {
	return &SignerSignHostKeyOK{}
}

/*SignerSignHostKeyOK handles this case with default header values.

A successful response.
*/
type SignerSignHostKeyOK struct {
	Payload *models.V1alpha1SignHostKeyResponse
}

func (o *SignerSignHostKeyOK) Error() string {
	return fmt.Sprintf("[POST /sshsigner/v1alpha1/hostkey][%d] signerSignHostKeyOK  %+v", 200, o.Payload)
}

func (o *SignerSignHostKeyOK) GetPayload() *models.V1alpha1SignHostKeyResponse {
	return o.Payload
}

func (o *SignerSignHostKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1alpha1SignHostKeyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSignerSignHostKeyDefault creates a SignerSignHostKeyDefault with default headers values
func NewSignerSignHostKeyDefault(code int) *SignerSignHostKeyDefault {
	return &SignerSignHostKeyDefault{
		_statusCode: code,
	}
}

/*SignerSignHostKeyDefault handles this case with default header values.

An unexpected error response
*/
type SignerSignHostKeyDefault struct {
	_statusCode int

	Payload *models.RuntimeError
}

// Code gets the status code for the signer sign host key default response
func (o *SignerSignHostKeyDefault) Code() int {
	return o._statusCode
}

func (o *SignerSignHostKeyDefault) Error() string {
	return fmt.Sprintf("[POST /sshsigner/v1alpha1/hostkey][%d] Signer_SignHostKey default  %+v", o._statusCode, o.Payload)
}

func (o *SignerSignHostKeyDefault) GetPayload() *models.RuntimeError {
	return o.Payload
}

func (o *SignerSignHostKeyDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RuntimeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
