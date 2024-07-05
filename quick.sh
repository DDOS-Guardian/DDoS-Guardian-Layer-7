
bold=$(tput bold)
normal=$(tput sgr0)

prompt_non_empty() {
    local prompt_message=$1
    local user_input
    while true; do
        read -p "$prompt_message" user_input
        if [[ -n "$user_input" ]]; then
            echo "$user_input"
            return
        else
            echo "Input cannot be empty. Please try again."
        fi
    done
}

echo "${bold}###############################"
echo "##                           ##"
echo "##      DDoS Guardian        ##"
echo "##                           ##"
echo "###############################"
echo "${normal}"

echo "Warning: This script may only work for Ubuntu 20.04 or lower."
read -p "Press enter to continue..."

add_nginx_config() {
    local file=$1
    local nginx_path="/etc/nginx/sites-available/$file"
    local config1="lua_shared_dict ddos_guardian_limit_dict 10m;"
    local config2="access_by_lua_file /etc/nginx/conf.d/ddos-guardian-layer-7/protection.lua;"
    
    if ! grep -q "$config1" "$nginx_path"; then
        sed -i '1s/^/lua_shared_dict ddos_guardian_limit_dict 10m;\n/' "$nginx_path"
    else
        echo "Skipping: $config1 already found in $nginx_path"
    fi
    
    if ! grep -q "$config2" "$nginx_path"; then
        sed -i '/location \/ {/a \\taccess_by_lua_file /etc/nginx/conf.d/ddos-guardian-layer-7/protection.lua;' "$nginx_path"
    else
        echo "Skipping: $config2 already found in $nginx_path"
    fi
}

check_and_ask_override() {
    local path=$1
    local desc=$2
    
    if [ -d "$path" ]; then
        echo "$desc already exists."
        local choice=$(prompt_non_empty "Do you wish to override it? (Y/N): ")
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            sudo rm -rf "$path"
            return 0
        else
            echo "Skipping $desc setup."
            return 1
        fi
    fi
    return 0
}

sudo apt-get update
sudo apt-get install -y libnginx-mod-http-lua

echo "Choose your protection level:"
echo "1 - Layer 4"
echo "2 - Layer 7"
echo "3 - All"
protection_level=$(prompt_non_empty "Enter your choice (1/2/3): ")

if [[ "$protection_level" == "1" || "$protection_level" == "3" ]]; then
    echo "Setting up Layer 4 protection..."
    echo "Choose your Layer 4 protection type:"
    echo "1 - Standard"
    echo "2 - Advanced"
    layer4_choice=$(prompt_non_empty "Enter your choice (1/2): ")
    
    if [ "$layer4_choice" == "1" ]; then
        if check_and_ask_override "./setup_ddosguardian_service.sh" "Layer 4 Standard protection"; then
            chmod +x setup_ddosguardian_service.sh
            ./setup_ddosguardian_service.sh
        fi
    elif [ "$layer4_choice" == "2" ]; then
        if check_and_ask_override "./advanced.sh" "Layer 4 Advanced protection"; then
            chmod +x advanced.sh
            ./advanced.sh
        fi
    else
        echo "Invalid choice for Layer 4 protection."
        exit 1
    fi
fi

if [[ "$protection_level" == "2" || "$protection_level" == "3" ]]; then
    echo "Setting up Layer 7 protection..."
    
    if check_and_ask_override "/etc/nginx/conf.d/ddos-guardian-layer-7" "Layer 7 protection"; then
        sudo mkdir -p /etc/nginx/conf.d/ddos-guardian-layer-7
        sudo git clone https://github.com/DDOS-Guardian/DDoS-Guardian-Layer-7.git /etc/nginx/conf.d/ddos-guardian-layer-7
    
        file_names=$(prompt_non_empty "Enter the nginx configuration file names (comma-separated or 'all' for all files in /etc/nginx/sites-available): ")
    
        if [ "$file_names" == "all" ]; then
            for file in /etc/nginx/sites-available/*; do
                add_nginx_config "$(basename "$file")"
            done
        else
            IFS=',' read -ra files <<< "$file_names"
            for file in "${files[@]}"; do
                add_nginx_config "$file"
            done
        fi
    
        ip_whitelist=$(prompt_non_empty "Enter the IPs to whitelist (comma-separated, 'none' for no IPs, 'all' to whitelist all device IPs): ")
    
        whitelist_config=""
        if [ "$ip_whitelist" == "none" ]; then
            whitelist_config="whitelist_ips = {}"
        elif [ "$ip_whitelist" == "all" ]; then
            device_ips=$(hostname -I | tr ' ' ',')
            whitelist_config="whitelist_ips = {${device_ips%,}}"
        else
            whitelist_config="whitelist_ips = {${ip_whitelist}}"
        fi
    
        lua_conf_path="/etc/nginx/conf.d/ddos-guardian-layer-7/protection.conf"
        sudo sed -i "s/whitelist_ips = {}/$whitelist_config/" "$lua_conf_path"
    
        turnstile_key=$(prompt_non_empty "Enter your Cloudflare Turnstile Key: ")
    
        if [ -n "$turnstile_key" ]; then
            if curl -s "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/generate" | grep -q "success"; then
                echo "Key valid"
                sudo sed -i "s/SITE-KEY/$turnstile_key/" "$lua_conf_path"
            else
                echo "Invalid Turnstile Key."
                exit 1
            fi
        else
            echo "Turnstile Key cannot be empty."
            exit 1
        fi
    fi
fi

sudo systemctl restart nginx

echo "DDoS Guardian setup is complete!"
