package main

import (
	"crypto/sha512"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
	"net/http"
	"os"
	"time"
)

type License struct {
	ID                   int            `gorm:"primaryKey" json:"id"`
	ActivationCode       string         `gorm:"index:idx_activation_code" json:"activation_code"`
	ProtectedMachineCode string         `gorm:"index:idx_protected_machine_code" json:"protected_machine_code"`
	CreatedAt            time.Time      `json:"created_at" json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at" json:"updated_at"`
	DeletedAt            gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

type RequestDTO struct {
	ProtectedMachineCode string `gorm:"protected_machine_code" json:"protected_machine_code"`
	ActivationCode       string `gorm:"index:idx_activation_code" json:"activation_code"`
}

func JsonHttpResponse(c *gin.Context, code int, message string, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"code":    code,
		"message": message,
		"data":    data,
	})
}

func generateSecretKey(s string) string {
	secretKey := ""
	for i := 0; i < 10; i++ {
		hash := sha512.New()
		hash.Write([]byte(s))
		hashedBytes := hash.Sum(nil)
		s = fmt.Sprintf("%x", hashedBytes)
		secretKey = s
	}
	return secretKey
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	logFile, _ := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	defer logFile.Close()
	logger := log.New(logFile, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	db, _ := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	err := db.AutoMigrate(&License{})
	if err != nil {
		return
	}
	r := gin.Default()
	r.Use(CORSMiddleware())
	r.POST("/", func(c *gin.Context) {
		var dto RequestDTO
		c.ShouldBindJSON(&dto)
		logger.Printf("Received authorization request: %#v\n", dto)

		var licenses []License
		db.Model(&License{}).Where("activation_code = ?", dto.ActivationCode).Limit(1).Find(&licenses)
		if len(licenses) == 0 {
			JsonHttpResponse(c, 2, "无此激活码，验证失败", nil)
		} else {
			if licenses[0].ProtectedMachineCode != "" {
				if licenses[0].ProtectedMachineCode != dto.ProtectedMachineCode {
					logger.Println("激活码已经绑定其他机器，无法绑定本机")
					JsonHttpResponse(c, 3, "激活码已经绑定其他机器，无法绑定本机", nil)
				} else {
					logger.Println("success")
					JsonHttpResponse(c, 0, "success", generateSecretKey(dto.ProtectedMachineCode))
				}
			} else {
				license := licenses[0]
				license.ProtectedMachineCode = dto.ProtectedMachineCode
				db.Model(License{}).Where("activation_code = ?", licenses[0].ActivationCode).Updates(&license)
				logger.Println("success")
				JsonHttpResponse(c, 0, "success", generateSecretKey(dto.ProtectedMachineCode))
			}
		}
	})
	err = r.Run("127.0.0.1:8090")
	if err != nil {
		return
	}
}
