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

var DB *gorm.DB

type License struct {
	ID                   int            `gorm:"primaryKey" json:"id"`
	ActivationCode       string         `gorm:"index:idx_activation_code" json:"activation_code"`
	ProtectedMachineCode string         `gorm:"index:idx_protected_machine_code" json:"protected_machine_code"`
	Used                 bool           `gorm:"index:idx_used" json:"used"`
	CreatedAt            time.Time      `json:"created_at" json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at" json:"updated_at"`
	DeletedAt            gorm.DeletedAt `gorm:"index" json:"deleted_at"`
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

func generateActivationCode() {
	const SECRET = "random_seed_1234567890"
	var licenses []License
	for it := 0; it < 1000; it++ {
		hash := sha512.New()
		hash.Write([]byte(time.Now().String() + SECRET))
		hashedBytes := hash.Sum(nil)
		code := fmt.Sprintf("%x", hashedBytes)
		licenses = append(licenses, License{ActivationCode: code, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	}
	DB.Create(&licenses)
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	logFile, _ := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	defer logFile.Close()
	logger := log.New(logFile, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	DB, _ = gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	err := DB.AutoMigrate(&License{})
	if err != nil {
		return
	}
	r := gin.Default()
	r.Use(CORSMiddleware())
	r.POST("/", func(c *gin.Context) {
		type RequestDTO struct {
			ProtectedMachineCode string `gorm:"protected_machine_code" json:"protected_machine_code"`
			ActivationCode       string `gorm:"index:idx_activation_code" json:"activation_code"`
		}

		var dto RequestDTO
		c.ShouldBindJSON(&dto)
		logger.Printf("Received authorization request: %#v\n", dto)

		var licenses []License
		DB.Model(&License{}).Where("activation_code = ?", dto.ActivationCode).Limit(1).Find(&licenses)
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
				DB.Model(License{}).Where("activation_code = ?", licenses[0].ActivationCode).Updates(&license)
				logger.Println("success")
				JsonHttpResponse(c, 0, "success", generateSecretKey(dto.ProtectedMachineCode))
			}
		}
	})
	r.POST("/code/get", func(c *gin.Context) {
		type RequestDTO struct {
			SecretKey string `json:"secret_key"`
		}
		var dto RequestDTO
		c.ShouldBindJSON(&dto)
		logger.Printf("Received code get request: %#v\n", dto)
		if dto.SecretKey != "ahfihfoh3r8hw83xnw94vnyt7348b87ybb6v563c34908v3x34rn7f" {
			JsonHttpResponse(c, 1, "secret key错误", nil)
			return
		}
		var licenses []License
		DB.Model(&License{}).Where("protected_machine_code = ? and used = ?", "", false).Limit(1).Find(&licenses)
		if len(licenses) == 0 {
			logger.Println("激活码已经用完, 正在生成新的激活码..")
			generateActivationCode()
			DB.Model(&License{}).Where("protected_machine_code = ? and used = ?", "", false).Limit(1).Find(&licenses)
		}
		logger.Println("找到了可用的激活码: ", licenses[0].ActivationCode)
		res := licenses[0].ActivationCode
		licenses[0].Used = true
		DB.Model(License{}).Where("activation_code = ?", licenses[0].ActivationCode).Updates(licenses[0])
		JsonHttpResponse(c, 0, "success", res)
	})
	err = r.Run("0.0.0.0:8090")
	if err != nil {
		return
	}
}
