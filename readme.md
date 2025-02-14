## How to use

```
package main

import (
	"fmt"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gin-gonic/gin"
	waf "github.com/oye-code/gin-coraza"
)

var (
	f = &waf.GinCoraza{}
)

func main() {
	f.Init(coraza.NewWAFConfig().
		WithDirectivesFromFile("wafrules/coraza.conf").
		WithDirectivesFromFile("wafrules/coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("wafrules/coreruleset/rules/*.conf").
		WithErrorCallback(func(error types.MatchedRule) {
			msg := error.ErrorLog()
			fmt.Printf("[logError][%s] %s\n", error.Rule().Severity(), msg)
		}))

	r := gin.Default()
	r.Use(f.GinCoraza())
	//default auto register c.Request.URL.Path and enable all check functions
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	r.POST("/ctx", func(c *gin.Context) {
		f.RegisertPath(c.Request.URL.Path,
			waf.Waf{IsEnable: true,
				CheckReqHeader:  true,
				CheckReqBody:    true,
				CheckRespHeader: true,
				CheckRespBody:   true,
			})
		//c.Header("Waf", "From OYE")
		//fmt.Println(c.GetRawData())
		c.String(http.StatusOK, "ok")
	})

	r.GET("/user/:name/*action", func(c *gin.Context) {
		//manual register path but Only effective after the first request
		f.RegisertPath(c.Request.URL.Path,
			waf.Waf{IsEnable: true,
				CheckReqHeader:  true,
				CheckReqBody:    false,
				CheckRespHeader: true,
				CheckRespBody:   true,
			})
		name := c.Param("name")
		action := c.Param("action")
		message := name + " is " + action
		c.String(http.StatusOK, message)
	})

	r.Run()
}
```