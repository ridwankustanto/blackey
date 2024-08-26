# Blackey: Simple yet Powerful (enough) API Key Management 🔑

Hey there! 👋 Welcome to Blackey, my personal project to solve the headache of API key management. If you're tired of reinventing the wheel for every project, you're in the right place!

## What's This All About? 🤔

Ever found yourself coding API key validation over and over? Yeah, me too. That's why I created Blackey. It's a Go module that handles all the API key management stuff, so you can focus on building cool stuff.

## What Can Blackey Do? 🚀

- Generate and validate API keys securely
- Block requests from unwanted IPs
- Limit how often an API key can be used (rate limiting)
- Handle CORS stuff without the hassle
- Keep track of how your API keys are being used
- Set up special "root" keys for admin tasks
- Automatically set up the database tables you need
- Work smoothly even when lots of people are using your API at once
- Set usage limits for API keys
- Make API keys expire after a certain time

## How It Works Under the Hood 🛠️

Blackey uses a PostgreSQL database to keep track of everything. Here's a simple breakdown:

1. One table for API key info
2. Another for counting how often keys are used
3. And a third for detailed logs of key usage

It checks IPs, manages rate limits, and handles CORS all in one go. Every time an API key is used, Blackey updates the counts and logs the activity.

## Things I'm Still Working On 🚧

1. Moving the rate limiter to Redis for better performance
2. Actually implementing the country restriction feature (right now it's just a placeholder)
3. Making the metrics system work better for super busy APIs
4. Adding more tests to make sure everything works perfectly

## What's Next? 🔮

I've got big plans for Blackey:

1. Using Redis for even better rate limiting
2. Adding that country restriction feature using a cool GeoIP database
3. Making frequently used API keys load faster
4. Creating a simple web page to manage your API keys
5. Supporting more database

## How to Get Started 🏁

First, grab the code:

```bash
go get github.com/ridwankustanto/blackey
```

Make sure you've got a PostgreSQL database ready. Blackey will set up the tables it needs automatically.

## Quick Example 💨
For more example please take alook `example` directory. Here's a simple way to use Blackey in your project:

```go
package main

import (
    "database/sql"
    "fmt"
    "net/http"

    "github.com/ridwankustanto/blackey"
    _ "github.com/lib/pq"
)

func main() {
    // Connect to your database
    db, err := sql.Open("postgres", "your_connection_string")
    if err != nil {
        panic(err)
    }
    defer db.Close()

    // Set up Blackey
    err := blackey.Initialize(db, "myapi_", 16)
    if err != nil {
        panic(err)
    }

    // Custom error handler example 
    customErrorHandler := func(w http.ResponseWriter, message string, statusCode int) {
		response := map[string]interface{}{
			"error": message,
			"code":  statusCode,
			"data":  nil,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(response)
	}

	config := blackey.MiddlewareConfig{
		APIIDHeaderName:  "X-API-Key-ID",
		APIKeyHeaderName: "X-API-Key",
		HeaderPrefix:     "Bearer ",
		ErrorHandler:     customErrorHandler,
	}

    // Your API handler
    // Example implementation of middleware validation and chain middleware
    http.HandleFunc("/api/", logHelloMiddleware(blackey.ValidateAPIKey(config)(yourAPIHandler)))
    // or http.HandleFunc("/api/", blackey.ValidateAPIKey(config)(logHelloMiddleware(http.HandlerFunc(yourAPIHandler))))
	http.Handle("/api/create-key", blackey.IsRootKey(config)(http.HandlerFunc(createAPIKeyHandler)))

    http.ListenAndServe(":8080", nil)
}

func logHelloMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Hello, World!")
		next.ServeHTTP(w, r)
	})
}

func yourAPIHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hey, your API key works!")
}
```

On first initialize `blackey` you will get this message on your terminal,
```
Blackey initialized successfully. Root ID c157b152-fb12-4e16-b1f3-83e96aa00f09 and Key myapi_8V5SYcmvnDlnMyI-9aWSmA== 
IMPORTANT: Store this root key securely. It will not be shown again. You can check it on the database if needed.
```

## Where Can You Use This? 🌍

Blackey is pretty flexible:

1. If you're building a SaaS app and need to manage different customer access levels
2. For securing a public API
3. 🤔 Hmmmm what else? 

## Got Ideas or Found a Bug? 🐛

I'd love to hear from you! Here's how you can help:

1. If you find a problem, open an issue on GitHub

Want to contribute? Awesome!

1. Fork the repo
2. Make a new branch for your cool new feature
3. Commit your changes
4. Open a pull request and tell me all about what you did

Your help in making Blackey better is super appreciated! 🙌

## License

This project is licensed under the MIT License.