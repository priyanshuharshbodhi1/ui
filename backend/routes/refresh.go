package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kubestellar/ui/utils"
)

// RefreshTokenHandler generates a new JWT token using a valid refresh token
func RefreshTokenHandler(c *gin.Context) {
	var refreshData struct {
		RefreshToken string `json:"refreshToken" binding:"required"`
	}

	if err := c.ShouldBindJSON(&refreshData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate refresh token
	refreshClaims, err := utils.ValidateRefreshToken(refreshData.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Generate only a new access token, reuse the existing refresh token
	newToken, err := utils.GenerateAccessToken(refreshClaims.Username, refreshClaims.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating new access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":        newToken,
		"refreshToken": refreshData.RefreshToken, // Return the same refresh token
		"user": gin.H{
			"username":    refreshClaims.Username,
			"permissions": refreshClaims.Permissions,
		},
	})
}
