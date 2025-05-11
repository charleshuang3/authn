package oidc

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/charleshuang3/authn/internal/storage"
)

var (
	stateRE = regexp.MustCompile(`^[a-zA-Z0-9-_.]+$`)
)

type handleAuthorizeParams struct {
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
	State        string `form:"state" binding:"required"`
	Scope        string `form:"scope" binding:"required"`
}

// handleAuthorize handles the authorization request for the authorization code flow.
func (o *OpenIDProvider) handleAuthorize(c *gin.Context) {
	params := &handleAuthorizeParams{}

	if err := c.ShouldBindQuery(params); err != nil {
		c.String(http.StatusBadRequest, "Missing required parameters")
		return
	}

	if params.ResponseType != "code" {
		c.String(http.StatusBadRequest, "Unsupported response type, only 'code' is supported")
		return
	}

	if !stateRE.MatchString(params.State) {
		c.String(http.StatusBadRequest, "Invalid state parameter format")
		return
	}

	if _, ok := o.authStateStorage.Get(params.State); ok {
		// This should never happen unless the requester is cheating.
		c.String(http.StatusBadRequest, "Conflict state")
		return
	}

	// Fetch client from database using clientID
	client, err := storage.GetClientByID(o.db, params.ClientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.String(http.StatusBadRequest, "Client not found")
			return
		} else {
			logger.Error().Err(err).Msg("Failed to get client")
			c.String(http.StatusInternalServerError, "Database error")
			return
		}
	}

	// Verify scopes
	scopes := strings.Split(params.Scope, " ")
	if !client.VerifyScopesAllowed(scopes) {
		c.String(http.StatusBadRequest, "Invalid scope")
		return
	}

	// Check if redirectURI matches one of the registered URIs for the client
	if !client.VerifyRedirectURI(params.RedirectURI) {
		c.String(http.StatusBadRequest, "Invalid redirect URI")
		return
	}

	o.authStateStorage.Set(params.State, &storage.AuthState{
		ClientID:    params.ClientID,
		RedirectURI: params.RedirectURI,
		Scopes:      scopes,
	})

	// Return the login page with the state value.
	if err := o.RenderLoginPage(c.Writer, &LoginPageData{
		Title:              o.config.Title,
		AllowPasswordLogin: client.AllowPasswordLogin,
		AllowGoogleLogin:   client.AllowGoogleLogin,
		State:              params.State,
		GoogleLoginURL:     o.config.SSO.Google.oauth2Config().AuthCodeURL(params.State),
	}); err != nil {
		logger.Error().Err(err).Msg("Failed to render login page")
		c.String(http.StatusInternalServerError, "Failed to render login page")
	}
}

//go:embed templates/login_page.html
var loginPageTemplateFile string

// loginPageTemplate is the HTML template for the login page.
var loginPageTemplate = template.Must(template.New("loginPage").Parse(loginPageTemplateFile))

// LoginPageData holds the data to be passed to the login page template.
type LoginPageData struct {
	Title              string
	AllowPasswordLogin bool
	AllowGoogleLogin   bool
	State              string
	GoogleLoginURL     string
}

// RenderLoginPage renders the login page with the provided state value.
func (o *OpenIDProvider) RenderLoginPage(w http.ResponseWriter, data *LoginPageData) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	return loginPageTemplate.Execute(w, data)
}
