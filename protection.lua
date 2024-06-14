local whitelist = {
    "127.0.0.1"
}

local blacklist = {
    
}

local function ip_in_list(ip, list)
    for _, value in ipairs(list) do
        if type(value) == "string" and value == ip then
            return true
        elseif type(value) == "table" and ngx.re.match(ip, value, "ijo") then
            return true
        end
    end
    return false
end

local function get_client_ip()
       local cf_ip = ngx.var.http_cf_connecting_ip
    if cf_ip then
        return cf_ip
    end

     local real_ip = ngx.var.http_x_forwarded_for
    if real_ip then
              local first_ip = real_ip:match("([^,%s]+)")
        if first_ip then
            return first_ip
        end
    end

       return ngx.var.remote_addr
end

local function generate_random_token()
    local charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local token = ""
    for i = 1, 8 do
        local index = math.random(1, #charset)
        token = token .. charset:sub(index, index)
    end
    return token
end

local function set_cookie()
    local token = generate_random_token()
    ngx.header['Set-Cookie'] = 'TOKEN=' .. token .. '; path=/; max-age=1800; HttpOnly'
end

local function delete_cookie()
    ngx.header['Set-Cookie'] = 'TOKEN=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly'
end

local function log_access(client_ip, request_uri, request_size, security_level, captcha_solved)
    local log_line = string.format('%s - %s - Requests: %s, Security: %s, Captcha: %s\n',
        client_ip,
        request_uri,
        request_size,
        security_level,
        captcha_solved
    )

    local ddos_guardian_dir = "/var/log/ddos-guardian"
    local ddos_guardian_log_file = ddos_guardian_dir .. "/access.log"

      local mkdir_command = "mkdir -p " .. ddos_guardian_dir
    os.execute(mkdir_command)

       local ddos_guardian_file, ddos_guardian_err = io.open(ddos_guardian_log_file, "a")
    if ddos_guardian_file then
        local success, write_err = ddos_guardian_file:write(log_line)
        if not success then
            ngx.log(ngx.ERR, "Failed to write to ddos-guardian access log file: " .. write_err)
        end
        ddos_guardian_file:close()
    else
        ngx.log(ngx.ERR, "Failed to open ddos-guardian access log file: " .. ddos_guardian_err)
    end
end

local function display_recaptcha(client_ip)
    ngx.log(ngx.ERR, "Displaying reCAPTCHA for IP: " .. client_ip)
    ngx.header.content_type = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>Checking Your Browser...</title>
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?compat=recaptcha" async defer></script>
            <style>
                html, body {
                    height: 100%%;
                    margin: 0;
                    padding: 0;
                    background-color: #1b1c30;
                    color: #FFF;
                    font-family: Arial, Helvetica, sans-serif;
                }
                .box {
                    border: 5px solid #2e2f4d;
                    background-color: #222339;
                    border-radius: 3px;
                    text-align: center;
                    padding: 70px 0;
                    width: 100%%;
                    height: 100%%;
                }
            </style>
            <script>
                function onSubmit(token) {
                    document.cookie = "TOKEN=" + token + "; max-age=1800; path=/";
                    window.location.reload();
                }
            </script>
        </head>
        <body>
            <div class="box">
                <h1>Checking Your Browser...</h1>
                <p>Protected By DDOS Guardian</p>
                <div class="g-recaptcha" data-sitekey="SITE-KEY" data-callback="onSubmit"></div>
            </div>
        </body>
        </html>
    ]])
    log_access(client_ip, ngx.var.request_uri, ngx.var.request_length, "Medium", "false")
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function display_blacklist_page(client_ip)
    ngx.log(ngx.ERR, "Displaying blacklist page for IP: " .. client_ip)
    ngx.header.content_type = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied</title>
            <style>
                html, body {
                    height: 100%%;
                    margin: 0;
                    padding: 0;
                    background-color: #1b1c30;
                    color: #FFF;
                    font-family: Arial, Helvetica, sans-serif;
                }
                .box {
                    border: 5px solid #2e2f4d;
                    background-color: #222339;
                    border-radius: 3px;
                    text-align: center;
                    padding: 70px 0;
                    width: 100%%;
                    height: 100%%;
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h1>Access Denied</h1>
                <p>Your IP address has been blacklisted. Please contact the site administrator for assistance.</p>
            </div>
        </body>
        </html>
    ]])
    delete_cookie()
    log_access(client_ip, ngx.var.request_uri, ngx.var.request_length, "High", "false")
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function sanitize_input(input)
       return string.gsub(input, "[;%(')]", "")
end


local limit_dict = ngx.shared.ddos_guardian_limit_dict



local function main()
    local client_ip = get_client_ip()
    local user_agent = ngx.var.http_user_agent or ""

    ngx.log(ngx.ERR, "Client IP: " .. tostring(client_ip))

    if ip_in_list(client_ip, blacklist) then
        ngx.log(ngx.ERR, "Client IP is blacklisted: " .. client_ip)
        display_blacklist_page(client_ip)
        return
    end



    if ngx.var.request_uri:match("%.php$") or
       ngx.var.request_uri:match("%.js$") or
       ngx.var.request_uri:match("%.html$") or
       ngx.var.request_uri:match("%.jsx$") or
       ngx.var.request_uri:match("%.ts$") or
       ngx.var.request_uri:match("%.tsx$") or
       ngx.var.request_uri:match("%.png$") or
       ngx.var.request_uri:match("%.jpg$") or
       ngx.var.request_uri:match("%.jpeg$") or
       ngx.var.request_uri:match("%.gif$") or
       ngx.var.request_uri:match("%.svg$") or
       ngx.var.request_uri:match("%.ico$") or
       ngx.var.request_uri:match("%.css$") or
       ngx.var.request_uri:match("%.woff$") or
       ngx.var.request_uri:match("%.woff2$") or
       ngx.var.request_uri:match("%.ttf$") or
       ngx.var.request_uri:match("%.eot$") or
       ngx.var.request_uri:match("%.otf$") or
       ngx.var.request_uri:match("%.webp$") then
        ngx.log(ngx.ERR, "Requested file type allowed")
        log_access(client_ip, ngx.var.request_uri, ngx.var.request_length, "Low", "false")
        return
    end

    if ip_in_list(client_ip, whitelist) then
        ngx.log(ngx.ERR, "Client IP is whitelisted: " .. client_ip)
        set_cookie() -- Generate token for whitelisted IP
        log_access(client_ip, ngx.var.request_uri, ngx.var.request_length, "Low", "false")
        return
    end

    if ngx.var.cookie_TOKEN then
        local token = ngx.var.cookie_TOKEN
        if #token >= 5 then
            ngx.log(ngx.ERR, "Valid token cookie found")
            log_access(client_ip, ngx.var.request_uri, ngx.var.request_length, "Low", "true")
            return 
        else
            ngx.log(ngx.ERR, "Invalid token length, removing cookie")
            delete_cookie()
        end
    end

    ngx.log(ngx.ERR, "Client IP is not whitelisted, showing reCAPTCHA")
    display_recaptcha(client_ip)
end

main()
