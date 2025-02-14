package waf

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gin-gonic/gin"
)

type Waf struct {
	IsEnable        bool
	CheckReqHeader  bool
	CheckReqBody    bool
	CheckRespHeader bool
	CheckRespBody   bool
	IsRegister      bool
}

const (
	IsEnable        = true
	CheckReqHeader  = true
	CheckReqBody    = true
	CheckRespHeader = true
	CheckRespBody   = true
	IsRegister      = true
)

type GinCoraza struct {
	Waf    map[string]Waf
	Coraza coraza.WAF
}

func (waf *GinCoraza) Init(cfg coraza.WAFConfig) {
	waf.Waf = map[string]Waf{}
	c, err := coraza.NewWAF(cfg)
	if err != nil {
		panic(err)
	}
	waf.Coraza = c
}

func (waf *GinCoraza) PreRegisertPath(fullPath string) {
	if val, exists := waf.Waf[fullPath]; exists {
		if val.IsRegister {
			return
		}
	}
	waf.Waf[fullPath] = Waf{IsEnable: IsEnable, CheckReqHeader: CheckReqHeader, CheckReqBody: CheckReqBody, CheckRespHeader: CheckReqHeader, CheckRespBody: CheckReqBody, IsRegister: !IsRegister}
}

func (waf *GinCoraza) RegisertPath(fullPath string, isEnable, checkReqHeader, checkReqBody, checkRespHeader, checkRespBody bool) {
	if val, exists := waf.Waf[fullPath]; exists {
		if val.IsRegister {
			return
		}
	}
	waf.Waf[fullPath] = Waf{IsEnable: isEnable, CheckReqHeader: checkReqHeader, CheckReqBody: checkReqBody, CheckRespHeader: checkReqHeader, CheckRespBody: checkReqBody, IsRegister: IsRegister}
}

func (waf *GinCoraza) GinCoraza() gin.HandlerFunc {
	return func(c *gin.Context) {
		fullPath := c.Request.URL.Path
		waf.PreRegisertPath(fullPath)
		cfg := waf.Waf[fullPath]
		if !cfg.IsEnable {
			c.Next()
			return
		}

		tx := waf.Coraza.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			tx.Close()
		}()

		if tx.IsRuleEngineOff() {
			c.Next()
			return
		}

		req := c.Request

		var (
			client string
			cport  int
		)
		// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
		idx := strings.LastIndexByte(req.RemoteAddr, ':')
		if idx != -1 {
			client = req.RemoteAddr[:idx]
			cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
		}
		tx.ProcessConnection(client, cport, req.Host, 443)
		tx.ProcessURI(c.Request.URL.String(), req.Method, req.Proto[5:])

		if cfg.CheckReqHeader {
			if req.Host != "" {
				tx.AddRequestHeader("Host", req.Host)
				// This connector relies on the host header (now host field) to populate ServerName
				tx.SetServerName(req.Host)
			}

			if req.TransferEncoding != nil {
				tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
			}

			if in := tx.ProcessRequestHeaders(); in != nil {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		if cfg.CheckReqBody {
			if tx.IsRequestBodyAccessible() {
				// We only do body buffering if the transaction requires request
				// body inspection, otherwise we just let the request follow its
				// regular flow.
				if req.Body != nil && req.Body != http.NoBody {
					it, _, err := tx.ReadRequestBodyFrom(req.Body)
					if err != nil {
						fmt.Println(err.Error())
						c.AbortWithStatus(http.StatusForbidden)
						return
					}

					if it != nil {
						c.AbortWithStatus(http.StatusForbidden)
						return
					}

					rbr, err := tx.RequestBodyReader()
					if err != nil {
						fmt.Println(err.Error())
						c.AbortWithStatus(http.StatusForbidden)
						return
					}

					// Adds all remaining bytes beyond the coraza limit to its buffer
					// It happens when the partial body has been processed and it did not trigger an interruption
					bodyReader := io.MultiReader(rbr, req.Body)
					// req.Body is transparently reinizialied with a new io.ReadCloser.
					// The http handler will be able to read it.
					c.Request.Body = io.NopCloser(bodyReader)
				}

				it, err := tx.ProcessRequestBody()
				if err != nil {
					fmt.Println(err.Error())
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
				if it != nil {
					c.AbortWithStatus(http.StatusForbidden)
					return
				}

			}
		}

		oldwriter := c.Writer
		c.Writer = &responseWriter{
			tx:               tx,
			ResponseWriter:   oldwriter,
			checkRespHeaders: cfg.CheckRespHeader,
			checkRespBody:    cfg.CheckRespBody,
		}
		c.Next()
		if tx.IsInterrupted() {
			c.AbortWithStatus(403)
			return
		}
		if cfg.CheckRespBody {
			if tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() {
				if it, err := tx.ProcessResponseBody(); err != nil {
					c.AbortWithStatus(500)
					return
				} else if it != nil {
					c.AbortWithStatus(403)
					return
				}
			}

			reader, err := tx.ResponseBodyReader()
			if err != nil {
				fmt.Println(err.Error())
				c.AbortWithStatus(403)
				return
			}
			io.Copy(oldwriter, reader)
		}

	}
}

type responseWriter struct {
	gin.ResponseWriter
	tx               types.Transaction
	protocol         string
	headersProcessed bool
	size             int
	checkRespHeaders bool
	checkRespBody    bool
}

func (w responseWriter) Write(b []byte) (n int, err error) {
	if w.checkRespHeaders {
		if it := w.processResponseHeaders(); it != nil {
			// transaction was interrupted :(
			return
		}
	}
	w.WriteHeaderNow()
	if w.checkRespBody {
		in, n, err := w.tx.WriteResponseBody(b)
		if in != nil {
			return 0, err
		}
		w.size += n
		return n, nil
	}
	n, err = w.ResponseWriter.Write(b)
	w.size += n
	return
}

func (w *responseWriter) WriteString(s string) (n int, err error) {
	if w.checkRespHeaders {
		if it := w.processResponseHeaders(); it != nil {
			// transaction was interrupted :(
			return
		}
	}
	w.WriteHeaderNow()
	if w.checkRespBody {
		in, n, err := w.tx.WriteResponseBody([]byte(s))
		if in != nil {
			return 0, err
		}
		w.size += n
		return n, nil
	}
	n, err = io.WriteString(w.ResponseWriter, s)
	w.size += n
	return
}

func (w *responseWriter) processResponseHeaders() *types.Interruption {
	if w.headersProcessed || w.tx.Interruption() != nil {
		return w.tx.Interruption()
	}
	w.headersProcessed = true
	for k, vv := range w.ResponseWriter.Header() {
		for _, v := range vv {
			w.tx.AddResponseHeader(k, v)
		}
	}
	return w.tx.ProcessResponseHeaders(w.ResponseWriter.Status(), w.protocol)
}

func (w *responseWriter) Status() int {
	if w.tx.Interruption() != nil {
		return w.tx.Interruption().Status
	}
	return w.ResponseWriter.Status()
}

func (w *responseWriter) Size() int {
	return w.size
}
