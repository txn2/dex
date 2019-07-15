![token](https://raw.githubusercontent.com/txn2/token/master/mast.jpg)

TXN2 JWT token middleware for gin-gonic.


### gin-gonic Implementation

Includes:
```go
import (
	"github.com/gin-gonic/gin"
	"github.com/txn2/token"
)
```

Add token middleware:
```go
// gin router
r := gin.New()

// token middleware
jwt := token.NewJwt(token.JwtCfg{
    Exp:    10, // minutes
    EncKey: []byte("DZCAJZGByGb7pGc3zJKdQ9wGYKRDZpZETZN46tzTWFT"),
})

r.Use(jwt.GinHandler())
```

### Example

Run Source:
```bash
go run ./example/server.go --key="n2r5u8x/A?D(G+KbPdX"
```

Tokenize a JSON object:
```bash
TOKEN=$(curl -X POST http://localhost:8080/tokenize?raw=true   -d '{
    "id": "sysop",
    "description": "Global system operator",
    "display_name": "System Operator",
    "active": true,
    "sysop": true,
    "password": "REDACTED",
    "sections_all": false,
    "sections": [],
    "accounts": [],
    "admin_accounts": []
}') && echo $TOKEN
```

Validate the token:
```bash
curl http://localhost:8080/validate -H "Authorization: Bearer $TOKEN"
```