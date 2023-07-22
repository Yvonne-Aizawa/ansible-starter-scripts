external_url 'https://gitlab.{{domain }}'
gitlab_rails['gitlab_default_theme'] = 2
nginx['listen_port'] = 80
nginx['listen_https'] = false
grafana['enable'] = true
grafana['admin_password'] = 'admin'
letsencrypt['enable'] = false



registry_external_url 'https://registry.gitlab.{{domain}}'
registry['enable'] = true
gitlab_rails['registry_enabled'] = true
registry_nginx['enable'] = true
registry_nginx['listen_port'] = 5005
registry_nginx['listen_https'] = false
registry_nginx['proxy_set_headers'] = {
  "Host" => "$http_host",
  "X-Real-IP" => "$remote_addr",
  "X-Forwarded-For" => "$proxy_add_x_forwarded_for",
  "X-Forwarded-Proto" => "https",
  "X-Forwarded-Ssl" => "on"
}

gitlab_rails['rack_attack_git_basic_auth'] = {
   'enabled' => true,
   'ip_whitelist' => ["127.0.0.1"],
   'maxretry' => 10,
   'findtime' => 600,
   'bantime' => 136000
}
