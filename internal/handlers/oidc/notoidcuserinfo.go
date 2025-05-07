package oidc

import (
	"errors"
	"net/http"
	"time"

	"github.com/charleshuang3/authn/internal/storage"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type handleNotOIDCUserInfoParams struct {
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
	Username     string `form:"username" binding:"required"`
	Password     string `form:"password" binding:"required"`
}

type handleNotOIDCUserInfoResponse struct {
	Username   string `json:"username"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Roles      string `json:"roles"`
	Picture    string `json:"picture"`
	Expiration int64  `json:"exp"`
}

func (o *OpenIDProvider) handleNotOIDCUserInfo(c *gin.Context) {
	params := &handleNotOIDCUserInfoParams{}
	if err := c.ShouldBind(params); err != nil {
		c.String(http.StatusBadRequest, "Missing required parameters")
		return
	}

	cli, err := storage.GetClientByID(o.db, params.ClientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.String(http.StatusBadRequest, "Invalid client ID")
			return
		}
		logger.Error().Err(err).Msg("Database error during client lookup")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	if cli.Secret != params.ClientSecret {
		c.String(http.StatusBadRequest, "Invalid client secret")
		return
	}

	if !cli.AllowHTTPBasicAuth {
		c.String(http.StatusBadRequest, "Client does not allow HTTP basic auth")
		return
	}

	user, err := storage.GetUserByUsername(o.db, params.Username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.String(http.StatusBadRequest, "Invalid username")
			return
		}
		logger.Error().Err(err).Msg("Database error during user lookup")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	if !user.CheckPassword(params.Password) {
		c.String(http.StatusBadRequest, "Invalid password")
		return
	}

	handleNotOIDCUserInfoResponse := &handleNotOIDCUserInfoResponse{
		Username:   user.Username,
		Name:       user.Name,
		Email:      user.Email,
		Roles:      user.Roles,
		Picture:    user.Picture,
		Expiration: time.Now().Add(cli.AccessTokenTTLDuration()).Unix(),
	}

	c.JSON(http.StatusOK, handleNotOIDCUserInfoResponse)
}
