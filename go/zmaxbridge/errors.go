package zmaxbridge

import "fmt"

// ErrUnavailable ZMax sunucusuna ulaşılamadığında veya zaman aşımında döner.
type ErrUnavailable struct {
	Address string
	Cause   error
}

func (e *ErrUnavailable) Error() string {
	return fmt.Sprintf("zmaxbridge: sunucuya ulasilamadi (%s): %v", e.Address, e.Cause)
}

func (e *ErrUnavailable) Unwrap() error {
	return e.Cause
}

// ErrContractMismatch Go istemcisi ile ZMax sunucusunun sözleşme sürümü uyuşmadığında döner.
type ErrContractMismatch struct {
	ClientVersion string
	ServerVersion string
}

func (e *ErrContractMismatch) Error() string {
	return fmt.Sprintf("zmaxbridge: sozlesme surum uyusmazligi: istemci=%s, sunucu=%s", e.ClientVersion, e.ServerVersion)
}

// ErrRejected Yapılandırma doğrulama veya reload reddedildiğinde döner.
type ErrRejected struct {
	File    string
	Field   string
	Message string
}

func (e *ErrRejected) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("zmaxbridge: yapilandirma reddedildi [%s alan=%s]: %s", e.File, e.Field, e.Message)
	}
	return fmt.Sprintf("zmaxbridge: yapilandirma reddedildi [%s]: %s", e.File, e.Message)
}

