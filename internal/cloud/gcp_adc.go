package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

const adcHint = "run `gcloud auth application-default login`"

// ADCPath is the Application Default Credentials file google-auth and gcloud use, in their order: the account's
// `adc_file`, GOOGLE_APPLICATION_CREDENTIALS, then gcloud's well-known file (CLOUDSDK_CONFIG or ~/.config/gcloud;
// %APPDATA%/gcloud on Windows). `where` names the source without the path (reasons stay generic).
func ADCPath(cfg Account, deps Deps) (path, where string) {
	if f := cfg.Str("adc_file"); f != "" {
		return ExpandUser(f, deps.home()), "adc_file"
	}
	if f := deps.getenv("GOOGLE_APPLICATION_CREDENTIALS"); f != "" {
		return f, "GOOGLE_APPLICATION_CREDENTIALS"
	}
	dir := deps.getenv("CLOUDSDK_CONFIG")
	if dir == "" {
		if deps.GOOS == "windows" {
			dir = filepath.Join(deps.getenv("APPDATA"), "gcloud")
		} else {
			dir = filepath.Join(deps.home(), ".config", "gcloud")
		}
	}
	return filepath.Join(dir, "application_default_credentials.json"), "the gcloud default location"
}

// adcUser is the part of an authorized_user ADC file the refresh needs. It lives only for one acquisition.
type adcUser struct {
	clientID, clientSecret, refreshToken string
}

// readADC reads and checks the operator's ADC file: private, a user login (authorized_user), complete.
func readADC(cfg Account, deps Deps) (adcUser, error) {
	path, where := ADCPath(cfg, deps)
	data, err := readPrivateADC(path, where, deps.GOOS)
	if err != nil {
		return adcUser{}, err
	}
	v, err := dyn.Decode(data)
	if err != nil {
		return adcUser{}, failf("gcp adc: credentials unreadable (%s): JSONDecodeError", where)
	}
	d, isMap := v.(map[string]any)
	typ := dyn.Map(v)["type"]
	switch {
	case isMap && dyn.Str(typ) == "service_account":
		return adcUser{}, failf("gcp adc: a service-account key file is a long-lived credential and is refused: "+
			"%s (a user login) or use source workload_identity", adcHint)
	case !isMap || dyn.Str(typ) != "authorized_user":
		return adcUser{}, failf("gcp adc: credential type %s not supported (authorized_user expected: %s)", pyRepr(typ), adcHint)
	}
	u := adcUser{clientID: dyn.Text(d, "client_id"), clientSecret: dyn.Text(d, "client_secret"),
		refreshToken: dyn.Text(d, "refresh_token")}
	if u.clientID == "" || u.clientSecret == "" || u.refreshToken == "" {
		return adcUser{}, failf("gcp adc: incomplete authorized_user credentials (%s): %s", where, adcHint)
	}
	return u, nil
}

// readPrivateADC reads the ADC file, refusing one that group or others can read (not checked on Windows).
func readPrivateADC(path, where, goos string) ([]byte, error) {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, failf("gcp adc: no application default credentials (%s): %s", where, adcHint)
	}
	if err != nil {
		return nil, failf("gcp adc: credentials unreadable (%s): %s", where, pyExcName(err))
	}
	if goos != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, failf("gcp adc: credentials file (%s) is readable by group/others: chmod 600 it", where)
	}
	data, err := readSmallFile(path)
	if err != nil {
		return nil, failf("gcp adc: credentials unreadable (%s): %s", where, pyExcName(err))
	}
	return data, nil
}

// adcTokenSource: the operator's ADC (an authorized_user refresh token, read fresh now) as the source of the SDK's
// impersonated-service-account credentials: the refresh grant and generateAccessToken are x/oauth2's own flows. The
// ADC content lives only in this acquisition's token source; the operator's user token is never returned.
// (x/oauth2 takes no lifetime for this credential type: the service-account token lives Google's default hour.)
func (p *gcpProvider) adcTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	u, err := readADC(p.cfg, p.deps)
	if err != nil {
		return nil, err
	}
	conf, err := json.Marshal(map[string]any{"type": "impersonated_service_account",
		"service_account_impersonation_url": p.impersonationURL(),
		"source_credentials": map[string]any{"type": "authorized_user", "client_id": u.clientID,
			"client_secret": u.clientSecret, "refresh_token": u.refreshToken, "token_uri": p.oauthURL}})
	if err != nil {
		return nil, failf("gcp adc: %s", err)
	}
	creds, err := google.CredentialsFromJSONWithType(ctx, conf, google.ImpersonatedServiceAccount, gcpScope)
	if err != nil {
		return nil, failf("gcp adc: %s", firstLine(err.Error()))
	}
	return creds.TokenSource, nil
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
