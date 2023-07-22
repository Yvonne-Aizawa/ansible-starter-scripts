external_url 'https://gitlab.{{domain }}'
gitlab_rails['gitlab_default_theme'] = 2

### Default project feature settings
# gitlab_rails['gitlab_default_projects_features_issues'] = true
# gitlab_rails['gitlab_default_projects_features_merge_requests'] = true
# gitlab_rails['gitlab_default_projects_features_wiki'] = true
# gitlab_rails['gitlab_default_projects_features_snippets'] = true
# gitlab_rails['gitlab_default_projects_features_builds'] = true
# gitlab_rails['gitlab_default_projects_features_container_registry'] = true

### Automatic issue closing
###! See https://docs.gitlab.com/ee/customization/issue_closing.html for more
###! information about this pattern.
# gitlab_rails['gitlab_issue_closing_pattern'] = "\b((?:[Cc]los(?:e[sd]?|ing)|\b[Ff]ix(?:e[sd]|ing)?|\b[Rr]esolv(?:e[sd]?|ing)|\b[Ii]mplement(?:s|ed|ing)?)(:?) +(?:(?:issues? +)?%{issue_ref}(?:(?:, *| +and +)?)|([A-Z][A-Z0-9_]+-\d+))+)"

### Download location
###! When a user clicks e.g. 'Download zip' on a project, a temporary zip file
###! is created in the following directory.
###! Should not be the same path, or a sub directory of any of the `git_data_dirs`
# gitlab_rails['gitlab_repository_downloads_path'] = 'tmp/repositories'

### Gravatar Settings
# gitlab_rails['gravatar_plain_url'] = 'http://www.gravatar.com/avatar/%{hash}?s=%{size}&d=identicon'
# gitlab_rails['gravatar_ssl_url'] = 'https://secure.gravatar.com/avatar/%{hash}?s=%{size}&d=identicon'

### Auxiliary jobs
###! Periodically executed jobs, to self-heal Gitlab, do external
###! synchronizations, etc.
###! Docs: https://github.com/ondrejbartas/sidekiq-cron#adding-cron-job
###!       https://docs.gitlab.com/ee/ci/yaml/index.html#artifactsexpire_in
# gitlab_rails['stuck_ci_jobs_worker_cron'] = "0 0 * * *"
# gitlab_rails['expire_build_artifacts_worker_cron'] = "*/7 * * * *"
# gitlab_rails['environments_auto_stop_cron_worker_cron'] = "24 * * * *"
# gitlab_rails['pipeline_schedule_worker_cron'] = "19 * * * *"
# gitlab_rails['ci_archive_traces_cron_worker_cron'] = "17 * * * *"
# gitlab_rails['repository_check_worker_cron'] = "20 * * * *"
# gitlab_rails['admin_email_worker_cron'] = "0 0 * * 0"
# gitlab_rails['personal_access_tokens_expiring_worker_cron'] = "0 1 * * *"
# gitlab_rails['personal_access_tokens_expired_notification_worker_cron'] = "0 2 * * *"
# gitlab_rails['repository_archive_cache_worker_cron'] = "0 * * * *"
# gitlab_rails['pages_domain_verification_cron_worker'] = "*/15 * * * *"
# gitlab_rails['pages_domain_ssl_renewal_cron_worker'] = "*/10 * * * *"
# gitlab_rails['pages_domain_removal_cron_worker'] = "47 0 * * *"
# gitlab_rails['remove_unaccepted_member_invites_cron_worker'] = "10 15 * * *"
# gitlab_rails['schedule_migrate_external_diffs_worker_cron'] = "15 * * * *"
# gitlab_rails['ci_platform_metrics_update_cron_worker'] = '47 9 * * *'
# gitlab_rails['analytics_usage_trends_count_job_trigger_worker_cron'] = "50 23 */1 * *"
# gitlab_rails['member_invitation_reminder_emails_worker_cron'] = "0 0 * * *"
# gitlab_rails['user_status_cleanup_batch_worker_cron'] = "* * * * *"
# gitlab_rails['namespaces_in_product_marketing_emails_worker_cron'] = "0 9 * * *"
# gitlab_rails['ssh_keys_expired_notification_worker_cron'] = "0 2 * * *"
# gitlab_rails['ssh_keys_expiring_soon_notification_worker_cron'] = "0 1 * * *"
# gitlab_rails['loose_foreign_keys_cleanup_worker_cron'] = "*/5 * * * *"
# gitlab_rails['ci_runner_versions_reconciliation_worker_cron'] = "@daily"
# gitlab_rails['ci_runners_stale_machines_cleanup_worker_cron'] = "36 4 * * *"

### Webhook Settings
###! Number of seconds to wait for HTTP response after sending webhook HTTP POST
###! request (default: 10)
# gitlab_rails['webhook_timeout'] = 10

### GraphQL Settings
###! Tells the rails application how long it has to complete a GraphQL request.
###! We suggest this value to be higher than the database timeout value
###! and lower than the worker timeout set in puma. (default: 30)
# gitlab_rails['graphql_timeout'] = 30

### Trusted proxies
###! Customize if you have GitLab behind a reverse proxy which is running on a
###! different machine.
###! **Add the IP address for your reverse proxy to the list, otherwise users
###!   will appear signed in from that address.**
# gitlab_rails['trusted_proxies'] = []

### Content Security Policy
####! Customize if you want to enable the Content-Security-Policy header, which
####! can help thwart JavaScript cross-site scripting (XSS) attacks.
####! See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
# gitlab_rails['content_security_policy'] = {
#  'enabled' => false,
#  'report_only' => false,
#  # Each directive is a String (e.g. "'self'").
#  'directives' => {
#    'base_uri' => nil,
#    'child_src' => nil,
#    'connect_src' => nil,
#    'default_src' => nil,
#    'font_src' => nil,
#    'form_action' => nil,
#    'frame_ancestors' => nil,
#    'frame_src' => nil,
#    'img_src' => nil,
#    'manifest_src' => nil,
#    'media_src' => nil,
#    'object_src' => nil,
#    'script_src' => nil,
#    'style_src' => nil,
#    'worker_src' => nil,
#    'report_uri' => nil,
#  }
# }

### Allowed hosts
###! Customize the `host` headers that should be catered by the Rails
###! application. By default, everything is allowed.
# gitlab_rails['allowed_hosts'] = []

### Monitoring settings
###! IP whitelist controlling access to monitoring endpoints
# gitlab_rails['monitoring_whitelist'] = ['127.0.0.0/8', '::1/128']

### Shutdown settings
###! Defines an interval to block healthcheck,
###! but continue accepting application requests.
# gitlab_rails['shutdown_blackout_seconds'] = 10

### Microsoft Graph Mailer
###! Allows delivery of emails using Microsoft Graph API with OAuth 2.0 client
###! credentials flow.
###! Docs: https://docs.gitlab.com/omnibus/settings/microsoft_graph_mailer.html
# gitlab_rails['microsoft_graph_mailer_enabled'] = false
# gitlab_rails['microsoft_graph_mailer_user_id'] = "YOUR-USER-ID"
# gitlab_rails['microsoft_graph_mailer_tenant'] = "YOUR-TENANT-ID"
# gitlab_rails['microsoft_graph_mailer_client_id'] = "YOUR-CLIENT-ID"
# gitlab_rails['microsoft_graph_mailer_client_secret'] = "YOUR-CLIENT-SECRET-ID"
# gitlab_rails['microsoft_graph_mailer_azure_ad_endpoint'] = "https://login.microsoftonline.com"
# gitlab_rails['microsoft_graph_mailer_graph_endpoint'] = "https://graph.microsoft.com"

### Reply by email
###! Allow users to comment on issues and merge requests by replying to
###! notification emails.
###! Docs: https://docs.gitlab.com/ee/administration/reply_by_email.html
# gitlab_rails['incoming_email_enabled'] = true

#### Incoming Email Address
####! The email address including the `%{key}` placeholder that will be replaced
####! to reference the item being replied to.
####! **The placeholder can be omitted but if present, it must appear in the
####!   "user" part of the address (before the `@`).**
# gitlab_rails['incoming_email_address'] = "gitlab-incoming+%{key}@gmail.com"

#### Email account username
####! **With third party providers, this is usually the full email address.**
####! **With self-hosted email servers, this is usually the user part of the
####!   email address.**
# gitlab_rails['incoming_email_email'] = "gitlab-incoming@gmail.com"

#### Email account password
# gitlab_rails['incoming_email_password'] = "[REDACTED]"

#### IMAP Settings
# gitlab_rails['incoming_email_host'] = "imap.gmail.com"
# gitlab_rails['incoming_email_port'] = 993
# gitlab_rails['incoming_email_ssl'] = true
# gitlab_rails['incoming_email_start_tls'] = false

#### Incoming Mailbox Settings (via `mail_room`)
####! The mailbox where incoming mail will end up. Usually "inbox".
# gitlab_rails['incoming_email_mailbox_name'] = "inbox"
####! The IDLE command timeout.
# gitlab_rails['incoming_email_idle_timeout'] = 60
####! The file name for internal `mail_room` JSON logfile
# gitlab_rails['incoming_email_log_file'] = "/var/log/gitlab/mailroom/mail_room_json.log"
####! This marks incoming messages deleted after delivery.
####! If you are using Microsoft Graph API instead of IMAP, set this to false to retain
####! messages in the inbox since deleted messages are auto-expunged after some time.
# gitlab_rails['incoming_email_delete_after_delivery'] = true
####! Permanently remove messages from the mailbox when they are marked as deleted after delivery
####! Only applies to IMAP. Microsoft Graph will auto-expunge any deleted messages.
# gitlab_rails['incoming_email_expunge_deleted'] = false

#### Inbox options (for Microsoft Graph)
# gitlab_rails['incoming_email_inbox_method'] = 'microsoft_graph'
# gitlab_rails['incoming_email_inbox_options'] = {
#    'tenant_id': 'YOUR-TENANT-ID',
#    'client_id': 'YOUR-CLIENT-ID',
#    'client_secret': 'YOUR-CLIENT-SECRET',
#    'poll_interval': 60  # Optional
# }

#### How incoming emails are delivered to Rails process. Accept either sidekiq
#### or webhook. The default config is webhook.
# gitlab_rails['incoming_email_delivery_method'] = "webhook"

#### Token to authenticate webhook requests. The token must be exactly 32 bytes,
#### encoded with base64
# gitlab_rails['incoming_email_auth_token'] = nil

####! The format of mail_room crash logs
# mailroom['exit_log_format'] = "plain"

### Consolidated (simplified) object storage configuration
###! This uses a single credential for object storage with multiple buckets.
###! It also enables Workhorse to upload files directly with its own S3 client
###! instead of using pre-signed URLs.
###!
###! This configuration will only take effect if the object_store
###! sections are not defined within the types. For example, enabling
###! gitlab_rails['artifacts_object_store_enabled'] or
###! gitlab_rails['lfs_object_store_enabled'] will prevent the
###! consolidated settings from being used.
###!
###! Be sure to use different buckets for each type of object.
###! Docs: https://docs.gitlab.com/ee/administration/object_storage.html
# gitlab_rails['object_store']['enabled'] = false
# gitlab_rails['object_store']['connection'] = {}
# gitlab_rails['object_store']['storage_options'] = {}
# gitlab_rails['object_store']['proxy_download'] = false
# gitlab_rails['object_store']['objects']['artifacts']['bucket'] = nil
# gitlab_rails['object_store']['objects']['external_diffs']['bucket'] = nil
# gitlab_rails['object_store']['objects']['lfs']['bucket'] = nil
# gitlab_rails['object_store']['objects']['uploads']['bucket'] = nil
# gitlab_rails['object_store']['objects']['packages']['bucket'] = nil
# gitlab_rails['object_store']['objects']['dependency_proxy']['bucket'] = nil
# gitlab_rails['object_store']['objects']['terraform_state']['bucket'] = nil
# gitlab_rails['object_store']['objects']['ci_secure_files']['bucket'] = nil
# gitlab_rails['object_store']['objects']['pages']['bucket'] = nil

### Job Artifacts
# gitlab_rails['artifacts_enabled'] = true
# gitlab_rails['artifacts_path'] = "/var/opt/gitlab/gitlab-rails/shared/artifacts"
####! Job artifacts Object Store
####! Docs: https://docs.gitlab.com/ee/administration/job_artifacts.html#using-object-storage
# gitlab_rails['artifacts_object_store_enabled'] = false
# gitlab_rails['artifacts_object_store_proxy_download'] = false
# gitlab_rails['artifacts_object_store_remote_directory'] = "artifacts"
# gitlab_rails['artifacts_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'host' => 's3.amazonaws.com',
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }

### External merge request diffs
# gitlab_rails['external_diffs_enabled'] = false
# gitlab_rails['external_diffs_when'] = nil
# gitlab_rails['external_diffs_storage_path'] = "/var/opt/gitlab/gitlab-rails/shared/external-diffs"
# gitlab_rails['external_diffs_object_store_enabled'] = false
# gitlab_rails['external_diffs_object_store_proxy_download'] = false
# gitlab_rails['external_diffs_object_store_remote_directory'] = "external-diffs"
# gitlab_rails['external_diffs_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'host' => 's3.amazonaws.com',
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }

### Git LFS
# gitlab_rails['lfs_enabled'] = true
# gitlab_rails['lfs_storage_path'] = "/var/opt/gitlab/gitlab-rails/shared/lfs-objects"
# gitlab_rails['lfs_object_store_enabled'] = false
# gitlab_rails['lfs_object_store_proxy_download'] = false
# gitlab_rails['lfs_object_store_remote_directory'] = "lfs-objects"
# gitlab_rails['lfs_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'host' => 's3.amazonaws.com',
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }

### GitLab uploads
###! Docs: https://docs.gitlab.com/ee/administration/uploads.html
# gitlab_rails['uploads_directory'] = "/var/opt/gitlab/gitlab-rails/uploads"
# gitlab_rails['uploads_storage_path'] = "/opt/gitlab/embedded/service/gitlab-rails/public"
# gitlab_rails['uploads_base_dir'] = "uploads/-/system"
# gitlab_rails['uploads_object_store_enabled'] = false
# gitlab_rails['uploads_object_store_proxy_download'] = false
# gitlab_rails['uploads_object_store_remote_directory'] = "uploads"
# gitlab_rails['uploads_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'host' => 's3.amazonaws.com',
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }

### Terraform state
###! Docs: https://docs.gitlab.com/ee/administration/terraform_state
# gitlab_rails['terraform_state_enabled'] = true
# gitlab_rails['terraform_state_storage_path'] = "/var/opt/gitlab/gitlab-rails/shared/terraform_state"
# gitlab_rails['terraform_state_object_store_enabled'] = false
# gitlab_rails['terraform_state_object_store_remote_directory'] = "terraform"
# gitlab_rails['terraform_state_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'host' => 's3.amazonaws.com',
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }

### CI Secure Files
# gitlab_rails['ci_secure_files_enabled'] = false
# gitlab_rails['ci_secure_files_storage_path'] = "/var/opt/gitlab/gitlab-rails/shared/ci_secure_files"
# gitlab_rails['ci_secure_files_object_store_enabled'] = false
# gitlab_rails['ci_secure_files_object_store_remote_directory'] = "ci-secure-files"
# gitlab_rails['ci_secure_files_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'host' => 's3.amazonaws.com',
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }

### GitLab Pages
# gitlab_rails['pages_object_store_enabled'] = false
# gitlab_rails['pages_object_store_remote_directory'] = "pages"
# gitlab_rails['pages_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'host' => 's3.amazonaws.com',
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }
# gitlab_rails['pages_local_store_enabled'] = true
# gitlab_rails['pages_local_store_path'] = "/var/opt/gitlab/gitlab-rails/shared/pages"

### Impersonation settings
# gitlab_rails['impersonation_enabled'] = true

### Disable jQuery and CSS animations
# gitlab_rails['disable_animations'] = false

### Application settings cache expiry in seconds. (default: 60)
# gitlab_rails['application_settings_cache_seconds'] = 60

### Usage Statistics
# gitlab_rails['usage_ping_enabled'] = true

### GitLab Mattermost
###! These settings are void if Mattermost is installed on the same omnibus
###! install
# gitlab_rails['mattermost_host'] = "https://mattermost.example.com"

### LDAP Settings
###! Docs: https://docs.gitlab.com/omnibus/settings/ldap.html
###! **Be careful not to break the indentation in the ldap_servers block. It is
###!   in yaml format and the spaces must be retained. Using tabs will not work.**

# gitlab_rails['ldap_enabled'] = false
# gitlab_rails['prevent_ldap_sign_in'] = false

###! **remember to close this block with 'EOS' below**
# gitlab_rails['ldap_servers'] = YAML.load <<-'EOS'
#   main: # 'main' is the GitLab 'provider ID' of this LDAP server
#     label: 'LDAP'
#     host: '_your_ldap_server'
#     port: 389
#     uid: 'sAMAccountName'
#     bind_dn: '_the_full_dn_of_the_user_you_will_bind_with'
#     password: '_the_password_of_the_bind_user'
#     encryption: 'plain' # "start_tls" or "simple_tls" or "plain"
#     verify_certificates: true
#     smartcard_auth: false
#     active_directory: true
#     allow_username_or_email_login: false
#     lowercase_usernames: false
#     block_auto_created_users: false
#     base: ''
#     user_filter: ''
#     ## EE only
#     group_base: ''
#     admin_group: ''
#     sync_ssh_keys: false
#
#   secondary: # 'secondary' is the GitLab 'provider ID' of second LDAP server
#     label: 'LDAP'
#     host: '_your_ldap_server'
#     port: 389
#     uid: 'sAMAccountName'
#     bind_dn: '_the_full_dn_of_the_user_you_will_bind_with'
#     password: '_the_password_of_the_bind_user'
#     encryption: 'plain' # "start_tls" or "simple_tls" or "plain"
#     verify_certificates: true
#     smartcard_auth: false
#     active_directory: true
#     allow_username_or_email_login: false
#     lowercase_usernames: false
#     block_auto_created_users: false
#     base: ''
#     user_filter: ''
#     ## EE only
#     group_base: ''
#     admin_group: ''
#     sync_ssh_keys: false
# EOS

### Smartcard authentication settings
###! Docs: https://docs.gitlab.com/ee/administration/auth/smartcard.html
# gitlab_rails['smartcard_enabled'] = false
# gitlab_rails['smartcard_ca_file'] = "/etc/gitlab/ssl/CA.pem"
# gitlab_rails['smartcard_client_certificate_required_host'] = 'smartcard.gitlab.example.com'
# gitlab_rails['smartcard_client_certificate_required_port'] = 3444
# gitlab_rails['smartcard_required_for_git_access'] = false
# gitlab_rails['smartcard_san_extensions'] = false

### OmniAuth Settings
###! Docs: https://docs.gitlab.com/ee/integration/omniauth.html
# gitlab_rails['omniauth_enabled'] = nil
# gitlab_rails['omniauth_allow_single_sign_on'] = ['saml']
# gitlab_rails['omniauth_sync_email_from_provider'] = 'saml'
# gitlab_rails['omniauth_sync_profile_from_provider'] = ['saml']
# gitlab_rails['omniauth_sync_profile_attributes'] = ['email']
# gitlab_rails['omniauth_auto_sign_in_with_provider'] = 'saml'
# gitlab_rails['omniauth_block_auto_created_users'] = true
# gitlab_rails['omniauth_auto_link_ldap_user'] = false
# gitlab_rails['omniauth_auto_link_saml_user'] = false
# gitlab_rails['omniauth_auto_link_user'] = ['twitter']
# gitlab_rails['omniauth_external_providers'] = ['twitter', 'google_oauth2']
# gitlab_rails['omniauth_allow_bypass_two_factor'] = ['google_oauth2']
# gitlab_rails['omniauth_providers'] = [
#   {
#     "name" => "google_oauth2",
#     "app_id" => "YOUR APP ID",
#     "app_secret" => "YOUR APP SECRET",
#     "args" => { "access_type" => "offline", "approval_prompt" => "" }
#   }
# ]
# gitlab_rails['omniauth_cas3_session_duration'] = 28800
# gitlab_rails['omniauth_saml_message_max_byte_size'] = 250000

### FortiAuthenticator authentication settings
# gitlab_rails['forti_authenticator_enabled'] = false
# gitlab_rails['forti_authenticator_host'] = 'forti_authenticator.example.com'
# gitlab_rails['forti_authenticator_port'] = 443
# gitlab_rails['forti_authenticator_username'] = 'admin'
# gitlab_rails['forti_authenticator_access_token'] = 's3cr3t'

### FortiToken Cloud authentication settings
# gitlab_rails['forti_token_cloud_enabled'] = false
# gitlab_rails['forti_token_cloud_client_id'] = 'forti_token_cloud_client_id'
# gitlab_rails['forti_token_cloud_client_secret'] = 's3cr3t'

### Backup Settings
###! Docs: https://docs.gitlab.com/omnibus/settings/backups.html

# gitlab_rails['manage_backup_path'] = true
# gitlab_rails['backup_path'] = "/var/opt/gitlab/backups"
# gitlab_rails['backup_gitaly_backup_path'] = "/opt/gitlab/embedded/bin/gitaly-backup"

###! Docs: https://docs.gitlab.com/ee/raketasks/backup_restore.html#backup-archive-permissions
# gitlab_rails['backup_archive_permissions'] = 0644

# gitlab_rails['backup_pg_schema'] = 'public'

###! The duration in seconds to keep backups before they are allowed to be deleted
# gitlab_rails['backup_keep_time'] = 604800

# gitlab_rails['backup_upload_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AKIAKIAKI',
#   'aws_secret_access_key' => 'secret123',
#   # # If IAM profile use is enabled, remove aws_access_key_id and aws_secret_access_key
#   'use_iam_profile' => false
# }
# gitlab_rails['backup_upload_remote_directory'] = 'my.s3.bucket'
# gitlab_rails['backup_multipart_chunk_size'] = 104857600

###! **Turns on AWS Server-Side Encryption with Amazon S3-Managed Keys for
###!   backups**
# gitlab_rails['backup_encryption'] = 'AES256'
###! The encryption key to use with AWS Server-Side Encryption.
###! Setting this value will enable Server-Side Encryption with customer provided keys;
###!   otherwise S3-managed keys are used.
# gitlab_rails['backup_encryption_key'] = '<base64-encoded encryption key>'

###! **Turns on AWS Server-Side Encryption with Amazon SSE-KMS (AWS managed but customer-master key)
# gitlab_rails['backup_upload_storage_options'] = {
#  'server_side_encryption' => 'aws:kms',
#  'server_side_encryption_kms_key_id' => 'arn:aws:kms:YOUR-KEY-ID-HERE'
# }

###! **Specifies Amazon S3 storage class to use for backups. Valid values
###!   include 'STANDARD', 'STANDARD_IA', and 'REDUCED_REDUNDANCY'**
# gitlab_rails['backup_storage_class'] = 'STANDARD'

###! Skip parts of the backup. Comma separated.
###! Docs: https://docs.gitlab.com/ee/raketasks/backup_restore.html#excluding-specific-directories-from-the-backup
#gitlab_rails['env'] = {
#    "SKIP" => "db,uploads,repositories,builds,artifacts,lfs,registry,pages"
#}

### For setting up different data storing directory
###! Docs: https://docs.gitlab.com/omnibus/settings/configuration.html#store-git-data-in-an-alternative-directory
###! **If you want to use a single non-default directory to store git data use a
###!   path that doesn't contain symlinks.**
# git_data_dirs({
#   "default" => {
#     "path" => "/mnt/nfs-01/git-data"
#    }
# })

### Gitaly settings
# gitlab_rails['gitaly_token'] = 'secret token'

### For storing GitLab application uploads, eg. LFS objects, build artifacts
###! Docs: https://docs.gitlab.com/ee/development/shared_files.html
# gitlab_rails['shared_path'] = '/var/opt/gitlab/gitlab-rails/shared'

### For storing encrypted configuration files
###! Docs: https://docs.gitlab.com/ee/administration/encrypted_configuration.html
# gitlab_rails['encrypted_settings_path'] = '/var/opt/gitlab/gitlab-rails/shared/encrypted_settings'

### Wait for file system to be mounted
###! Docs: https://docs.gitlab.com/omnibus/settings/configuration.html#only-start-omnibus-gitlab-services-after-a-given-file-system-is-mounted
# high_availability['mountpoint'] = ["/var/opt/gitlab/git-data", "/var/opt/gitlab/gitlab-rails/shared"]

### GitLab Shell settings for GitLab
# gitlab_rails['gitlab_shell_ssh_port'] = 22
# gitlab_rails['gitlab_shell_git_timeout'] = 800

### Extra customization
# gitlab_rails['extra_google_analytics_id'] = '_your_tracking_id'
# gitlab_rails['extra_google_tag_manager_id'] = '_your_tracking_id'
# gitlab_rails['extra_one_trust_id'] = '_your_one_trust_id'
# gitlab_rails['extra_google_tag_manager_nonce_id'] = '_your_google_tag_manager_id'
# gitlab_rails['extra_bizible'] = false
# gitlab_rails['extra_matomo_url'] = '_your_matomo_url'
# gitlab_rails['extra_matomo_site_id'] = '_your_matomo_site_id'
# gitlab_rails['extra_matomo_disable_cookies'] = false
# gitlab_rails['extra_maximum_text_highlight_size_kilobytes'] = 512

##! Docs: https://docs.gitlab.com/omnibus/settings/environment-variables.html
# gitlab_rails['env'] = {
#   'BUNDLE_GEMFILE' => "/opt/gitlab/embedded/service/gitlab-rails/Gemfile",
#   'PATH' => "/opt/gitlab/bin:/opt/gitlab/embedded/bin:/bin:/usr/bin"
# }

# gitlab_rails['rack_attack_git_basic_auth'] = {
#   'enabled' => false,
#   'ip_whitelist' => ["127.0.0.1"],
#   'maxretry' => 10,
#   'findtime' => 60,
#   'bantime' => 3600
# }

# gitlab_rails['dir'] = "/var/opt/gitlab/gitlab-rails"
# gitlab_rails['log_directory'] = "/var/log/gitlab/gitlab-rails"

#### Change the initial default admin password and shared runner registration tokens.
####! **Only applicable on initial setup, changing these settings after database
####!   is created and seeded won't yield any change.**
# gitlab_rails['initial_root_password'] = "password"
# gitlab_rails['initial_shared_runners_registration_token'] = "token"

#### Toggle if root password should be printed to STDOUT during initialization
# gitlab_rails['display_initial_root_password'] = false

#### Toggle if initial root password should be written to /etc/gitlab/initial_root_password
# gitlab_rails['store_initial_root_password'] = true

#### Set path to an initial license to be used while bootstrapping GitLab.
####! **Only applicable on initial setup, future license updates need to be done via UI.
####! Updating the file specified in this path won't yield any change after the first reconfigure run.
# gitlab_rails['initial_license_file'] = '/etc/gitlab/company.gitlab-license'

#### Enable or disable automatic database migrations
# gitlab_rails['auto_migrate'] = true

#### This is advanced feature used by large gitlab deployments where loading
#### whole RAILS env takes a lot of time.
# gitlab_rails['rake_cache_clear'] = true

### GitLab database settings
###! Docs: https://docs.gitlab.com/omnibus/settings/database.html
###! **Only needed if you use an external database.**
# gitlab_rails['db_adapter'] = "postgresql"
# gitlab_rails['db_encoding'] = "unicode"
# gitlab_rails['db_collation'] = nil
# gitlab_rails['db_database'] = "gitlabhq_production"
# gitlab_rails['db_username'] = "gitlab"
# gitlab_rails['db_password'] = nil
# gitlab_rails['db_host'] = nil
# gitlab_rails['db_port'] = 5432
# gitlab_rails['db_socket'] = nil
# gitlab_rails['db_sslmode'] = nil
# gitlab_rails['db_sslcompression'] = 0
# gitlab_rails['db_sslrootcert'] = nil
# gitlab_rails['db_sslcert'] = nil
# gitlab_rails['db_sslkey'] = nil
# gitlab_rails['db_prepared_statements'] = false
# gitlab_rails['db_statements_limit'] = 1000
# gitlab_rails['db_connect_timeout'] = nil
# gitlab_rails['db_keepalives'] = nil
# gitlab_rails['db_keepalives_idle'] = nil
# gitlab_rails['db_keepalives_interval'] = nil
# gitlab_rails['db_keepalives_count'] = nil
# gitlab_rails['db_tcp_user_timeout'] = nil
# gitlab_rails['db_application_name'] = nil
# gitlab_rails['db_database_tasks'] = true


### GitLab Redis settings
###! Connect to your own Redis instance
###! Docs: https://docs.gitlab.com/omnibus/settings/redis.html

#### Redis TCP connection
# gitlab_rails['redis_host'] = "127.0.0.1"
# gitlab_rails['redis_port'] = 6379
# gitlab_rails['redis_ssl'] = false
# gitlab_rails['redis_password'] = nil
# gitlab_rails['redis_database'] = 0
# gitlab_rails['redis_enable_client'] = true

#### Redis local UNIX socket (will be disabled if TCP method is used)
# gitlab_rails['redis_socket'] = "/var/opt/gitlab/redis/redis.socket"

#### Sentinel support
####! To have Sentinel working, you must enable Redis TCP connection support
####! above and define a few Sentinel hosts below (to get a reliable setup
####! at least 3 hosts).
####! **You don't need to list every sentinel host, but the ones not listed will
####!   not be used in a fail-over situation to query for the new master.**
# gitlab_rails['redis_sentinels'] = [
#   {'host' => '127.0.0.1', 'port' => 26379},
# ]

#### Separate instances support
###! Docs: https://docs.gitlab.com/omnibus/settings/redis.html#running-with-multiple-redis-instances
# gitlab_rails['redis_cache_instance'] = nil
# gitlab_rails['redis_cache_sentinels'] = nil
# gitlab_rails['redis_queues_instance'] = nil
# gitlab_rails['redis_queues_sentinels'] = nil
# gitlab_rails['redis_shared_state_instance'] = nil
# gitlab_rails['redis_shared_state_sentinels'] = nil
# gitlab_rails['redis_trace_chunks_instance'] = nil
# gitlab_rails['redis_trace_chunks_sentinels'] = nil
# gitlab_rails['redis_actioncable_instance'] = nil
# gitlab_rails['redis_actioncable_sentinels'] = nil
# gitlab_rails['redis_rate_limiting_instance'] = nil
# gitlab_rails['redis_rate_limiting_sentinels'] = nil
# gitlab_rails['redis_sessions_instance'] = nil
# gitlab_rails['redis_sessions_sentinels'] = nil
# gitlab_rails['redis_repository_cache_instance'] = nil
# gitlab_rails['redis_repository_cache_sentinels'] = nil
# gitlab_rails['redis_yml_override'] = nil

################################################################################
## Container Registry settings
##! Docs: https://docs.gitlab.com/ee/administration/packages/container_registry.html
################################################################################

# registry_external_url 'https://registry.gitlab.yvonnetake.nl'

### Settings used by GitLab application
# gitlab_rails['registry_enabled'] = true
# gitlab_rails['registry_host'] = "registry.gitlab.example.com"
# gitlab_rails['registry_port'] = "5005"
# gitlab_rails['registry_path'] = "/var/opt/gitlab/gitlab-rails/shared/registry"

# Notification secret, it's used to authenticate notification requests to GitLab application
# You only need to change this when you use external Registry service, otherwise
# it will be taken directly from notification settings of your Registry
# gitlab_rails['registry_notification_secret'] = nil

###! **Do not change the following 3 settings unless you know what you are
###!   doing**
# gitlab_rails['registry_api_url'] = "http://127.0.0.1:5000"
# gitlab_rails['registry_key_path'] = "/var/opt/gitlab/gitlab-rails/certificate.key"
# gitlab_rails['registry_issuer'] = "omnibus-gitlab-issuer"

### Settings used by Registry application
# registry['enable'] = true
# registry['username'] = "registry"
# registry['group'] = "registry"
# registry['uid'] = nil
# registry['gid'] = nil
# registry['dir'] = "/var/opt/gitlab/registry"
# registry['registry_http_addr'] = "http:"
# registry['debug_addr'] = "localhost:5001"
# registry['log_directory'] = "/var/log/gitlab/registry"
# registry['env_directory'] = "/opt/gitlab/etc/registry/env"
# registry['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }
# registry['log_level'] = "info"
# registry['log_formatter'] = "text"
# registry['rootcertbundle'] = "/var/opt/gitlab/registry/certificate.crt"
# registry['health_storagedriver_enabled'] = true
# registry['middleware'] = nil
# registry['storage_delete_enabled'] = true
# registry['validation_enabled'] = false
# registry['autoredirect'] = false
# registry['compatibility_schema1_enabled'] = false

### Registry backend storage
###! Docs: https://docs.gitlab.com/ee/administration/packages/container_registry.html#configure-storage-for-the-container-registry
# registry['storage'] = {
#   's3' => {
#     'accesskey' => 's3-access-key',
#     'secretkey' => 's3-secret-key-for-access-key',
#     'bucket' => 'your-s3-bucket',
#     'region' => 'your-s3-region',
#     'regionendpoint' => 'your-s3-regionendpoint'
#   },
#   'redirect' => {
#     'disable' => false
#   }
# }

### Registry notifications endpoints
# registry['notifications'] = [
#   {
#     'name' => 'test_endpoint',
#     'url' => 'https://gitlab.example.com/notify2',
#     'timeout' => '500ms',
#     'threshold' => 5,
#     'backoff' => '1s',
#     'headers' => {
#       "Authorization" => ["AUTHORIZATION_EXAMPLE_TOKEN"]
#     }
#   }
# ]
### Default registry notifications
# registry['default_notifications_timeout'] = "500ms"
# registry['default_notifications_threshold'] = 5
# registry['default_notifications_backoff'] = "1s"
# registry['default_notifications_headers'] = {}

################################################################################
## Error Reporting and Logging with Sentry
################################################################################
# gitlab_rails['sentry_enabled'] = false
# gitlab_rails['sentry_dsn'] = 'https://<key>@sentry.io/<project>'
# gitlab_rails['sentry_clientside_dsn'] = 'https://<key>@sentry.io/<project>'
# gitlab_rails['sentry_environment'] = 'production'

################################################################################
## CI_JOB_JWT
################################################################################
##! RSA private key used to sign CI_JOB_JWT
# gitlab_rails['ci_jwt_signing_key'] = nil # Will be generated if not set.

################################################################################
## GitLab Workhorse
##! Docs: https://gitlab.com/gitlab-org/gitlab/-/blob/master/workhorse/README.md
################################################################################

# gitlab_workhorse['enable'] = true
# gitlab_workhorse['ha'] = false
# gitlab_workhorse['alt_document_root'] = nil

##! Duration to wait for all requests to finish (e.g. "10s" for 10
##! seconds). By default this is disabled to preserve the existing
##! behavior of fast shutdown. This should not be set higher than 30
##! seconds, since gitlab-ctl will wait up to 30 seconds (as defined by
##! the SVWAIT variable) and report a timeout error if the process has
##! not shut down.
# gitlab_workhorse['shutdown_timeout'] = nil
# gitlab_workhorse['listen_network'] = "unix"
# gitlab_workhorse['listen_umask'] = 000
# gitlab_workhorse['listen_addr'] = "/var/opt/gitlab/gitlab-workhorse/sockets/socket"
# gitlab_workhorse['auth_backend'] = "http://localhost:8080"

##! Enable Redis keywatcher, if this setting is not present it defaults to true
# gitlab_workhorse['workhorse_keywatcher'] = true

##! the empty string is the default in gitlab-workhorse option parser
# gitlab_workhorse['auth_socket'] = "''"

##! put an empty string on the command line
# gitlab_workhorse['pprof_listen_addr'] = "''"

# gitlab_workhorse['prometheus_listen_addr'] = "localhost:9229"

# gitlab_workhorse['dir'] = "/var/opt/gitlab/gitlab-workhorse"
# gitlab_workhorse['log_directory'] = "/var/log/gitlab/gitlab-workhorse"
# gitlab_workhorse['proxy_headers_timeout'] = "1m0s"

##! limit number of concurrent API requests, defaults to 0 which is unlimited
# gitlab_workhorse['api_limit'] = 0

##! limit number of API requests allowed to be queued, defaults to 0 which
##! disables queuing
# gitlab_workhorse['api_queue_limit'] = 0

##! duration after which we timeout requests if they sit too long in the queue
# gitlab_workhorse['api_queue_duration'] = "30s"

##! Long polling duration for job requesting for runners
# gitlab_workhorse['api_ci_long_polling_duration'] = "60s"

##! Propagate X-Request-Id if available. Workhorse will generate a random value otherwise.
# gitlab_workhorse['propagate_correlation_id'] = false

##! A list of CIDR blocks to allow for propagation of correlation ID.
##! propagate_correlation_id should also be set to true.
##! For example: %w(127.0.0.1/32 192.168.0.1/32)
# gitlab_workhorse['trusted_cidrs_for_propagation'] = nil

##! A list of CIDR blocks that must match remote IP addresses to use
##! X-Forwarded-For HTTP header for the actual client IP. Used in
##! conjuction with propagate_correlation_id and
##! trusted_cidrs_for_propagation.
##! For example: %w(127.0.0.1/32 192.168.0.1/32)
# gitlab_workhorse['trusted_cidrs_for_x_forwarded_for'] = nil

##! Log format: default is json, can also be text or none.
# gitlab_workhorse['log_format'] = "json"

# gitlab_workhorse['env_directory'] = "/opt/gitlab/etc/gitlab-workhorse/env"
# gitlab_workhorse['env'] = {
#   'PATH' => "/opt/gitlab/bin:/opt/gitlab/embedded/bin:/bin:/usr/bin",
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }

##! Resource limitations for the dynamic image scaler.
##! Exceeding these thresholds will cause Workhorse to serve images in their original size.
##!
##! Maximum number of scaler processes that are allowed to execute concurrently.
##! It is recommended for this not to exceed the number of CPUs available.
# gitlab_workhorse['image_scaler_max_procs'] = 4
##!
##! Maximum file size in bytes for an image to be considered eligible for rescaling
# gitlab_workhorse['image_scaler_max_filesize'] = 250000

##! Service name used to register GitLab Workhorse as a Consul service
# gitlab_workhorse['consul_service_name'] = 'workhorse'
##! Semantic metadata used when registering GitLab Workhorse as a Consul service
# gitlab_workhorse['consul_service_meta'] = {}

################################################################################
## GitLab User Settings
##! Modify default git user.
##! Docs: https://docs.gitlab.com/omnibus/settings/configuration.html#change-the-name-of-the-git-user-or-group
################################################################################

# user['username'] = "git"
# user['group'] = "git"
# user['uid'] = nil
# user['gid'] = nil

##! The shell for the git user
# user['shell'] = "/bin/sh"

##! The home directory for the git user
# user['home'] = "/var/opt/gitlab"

# user['git_user_name'] = "GitLab"
# user['git_user_email'] = "gitlab@#{node['fqdn']}"

################################################################################
## GitLab Puma
##! Tweak puma settings.
##! Docs: https://docs.gitlab.com/ee/administration/operations/puma.html
################################################################################

# puma['enable'] = true
# puma['ha'] = false
# puma['worker_timeout'] = 60
# puma['worker_processes'] = 2
# puma['min_threads'] = 4
# puma['max_threads'] = 4

### Advanced settings
# puma['listen'] = '127.0.0.1'
# puma['port'] = 8080
# puma['socket'] = '/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket'
# puma['somaxconn'] = 1024

### SSL settings
# puma['ssl_listen'] = nil
# puma['ssl_port'] = nil
# puma['ssl_certificate'] = nil
# puma['ssl_certificate_key'] = nil
# puma['ssl_client_certificate'] = nil
# puma['ssl_cipher_filter'] = nil
# puma['ssl_verify_mode'] = 'none'

# puma['pidfile'] = '/opt/gitlab/var/puma/puma.pid'
# puma['state_path'] = '/opt/gitlab/var/puma/puma.state'

###! **We do not recommend changing this setting**
# puma['log_directory'] = "/var/log/gitlab/puma"

### **Only change these settings if you understand well what they mean**
###! Docs: https://github.com/schneems/puma_worker_killer
# puma['per_worker_max_memory_mb'] = 1024

# puma['exporter_enabled'] = false
# puma['exporter_address'] = "127.0.0.1"
# puma['exporter_port'] = 8083
# puma['exporter_tls_enabled'] = false
# puma['exporter_tls_cert_path'] = ""
# puma['exporter_tls_key_path'] = ""

# puma['prometheus_scrape_scheme'] = 'http'
# puma['prometheus_scrape_tls_server_name'] = 'localhost'
# puma['prometheus_scrape_tls_skip_verification'] = false

##! Service name used to register Puma as a Consul service
# puma['consul_service_name'] = 'rails'
##! Semantic metadata used when registering Puma as a Consul service
# puma['consul_service_meta'] = {}

################################################################################
## GitLab Sidekiq
################################################################################

##! GitLab allows one to start multiple sidekiq processes. These
##! processes can be used to consume a dedicated set of queues. This
##! can be used to ensure certain queues are able to handle additional workload.
##! https://docs.gitlab.com/ee/administration/operations/extra_sidekiq_processes.html

# sidekiq['log_directory'] = "/var/log/gitlab/sidekiq"
# sidekiq['log_format'] = "json"
# sidekiq['shutdown_timeout'] = 4
# sidekiq['interval'] = nil
# sidekiq['max_concurrency'] = 20
# sidekiq['min_concurrency'] = nil

##! GitLab allows route a job to a particular queue determined by an array of ##! routing rules.
##! Each routing rule is a tuple of queue selector query and corresponding queue. By default,
##! the routing rules are not configured (empty array)

# sidekiq['routing_rules'] = []

##! Each entry in the queue_groups array denotes a group of queues that have to be processed by a
##! Sidekiq process. Multiple queues can be processed by the same process by
##! separating them with a comma within the group entry, a `*` will process all queues

# sidekiq['queue_groups'] = ['*']

##! Specifies where Prometheus metrics endpoints should be made available for Sidekiq processes.
# sidekiq['metrics_enabled'] = true
# sidekiq['exporter_log_enabled'] = false
# sidekiq['exporter_tls_enabled'] = false
# sidekiq['exporter_tls_cert_path'] = ""
# sidekiq['exporter_tls_key_path'] = ""
# sidekiq['listen_address'] = "localhost"
# sidekiq['listen_port'] = 8082

##! Specifies where health-check endpoints should be made available for Sidekiq processes.
##! Defaults to the same settings as for Prometheus metrics (see above).
# sidekiq['health_checks_enabled'] = true
# sidekiq['health_checks_listen_address'] = "localhost"
# sidekiq['health_checks_listen_port'] = 8092

##! Service name used to register Sidekiq as a Consul service
# sidekiq['consul_service_name'] = 'sidekiq'
##! Semantic metadata used when registering Sidekiq as a Consul service
# sidekiq['consul_service_meta'] = {}

################################################################################
## gitlab-shell
################################################################################

# gitlab_shell['audit_usernames'] = false
# gitlab_shell['log_level'] = 'INFO'
# gitlab_shell['log_format'] = 'json'
# gitlab_shell['http_settings'] = { user: 'username', password: 'password', ca_file: '/etc/ssl/cert.pem', ca_path: '/etc/pki/tls/certs'}
# gitlab_shell['log_directory'] = "/var/log/gitlab/gitlab-shell/"

# gitlab_shell['auth_file'] = "/var/opt/gitlab/.ssh/authorized_keys"

### Migration to Go feature flags
###! Docs: https://gitlab.com/gitlab-org/gitlab-shell#migration-to-go-feature-flags
# gitlab_shell['migration'] = { enabled: true, features: [] }

### Git trace log file.
###! If set, git commands receive GIT_TRACE* environment variables
###! Docs: https://git-scm.com/book/es/v2/Git-Internals-Environment-Variables#Debugging
###! An absolute path starting with / – the trace output will be appended to
###! that file. It needs to exist so we can check permissions and avoid
###! throwing warnings to the users.
# gitlab_shell['git_trace_log_file'] = "/var/log/gitlab/gitlab-shell/gitlab-shell-git-trace.log"

##! **We do not recommend changing this directory.**
# gitlab_shell['dir'] = "/var/opt/gitlab/gitlab-shell"

################################################################################
## gitlab-sshd
################################################################################

# gitlab_sshd['enable'] = false
# gitlab_sshd['generate_host_keys'] = true
# gitlab_sshd['dir'] = "/var/opt/gitlab/gitlab-sshd"

# gitlab-sshd outputs most logs to /var/log/gitlab/gitlab-shell/gitlab-shell.log.
# This directory only stores stdout/stderr output from the daemon.
# gitlab_sshd['log_directory'] = "/var/log/gitlab/gitlab-sshd/"

# gitlab_sshd['env_directory'] = '/opt/gitlab/etc/gitlab-sshd/env'
# gitlab_sshd['listen_address'] = 'localhost:2222'
# gitlab_sshd['metrics_address'] = 'localhost:9122'
# gitlab_sshd['concurrent_sessions_limit'] = 100
# gitlab_sshd['proxy_protocol'] = false
# gitlab_sshd['proxy_policy'] = 'use'
# gitlab_sshd['proxy_header_timeout'] = '500ms'
# gitlab_sshd['grace_period'] = 55
# gitlab_sshd['client_alive_interval'] = nil
# gitlab_sshd['ciphers'] = nil
# gitlab_sshd['kex_algorithms'] = nil
# gitlab_sshd['macs'] = nil
# gitlab_sshd['login_grace_time'] = 60
# gitlab_sshd['host_keys_dir'] = '/var/opt/gitlab/gitlab-sshd'
# gitlab_sshd['host_keys_glob'] = 'ssh_host_*_key'
# gitlab_sshd['host_certs_dir'] = '/var/opt/gitlab/gitlab-sshd'
# gitlab_sshd['host_certs_glob'] = 'ssh_host_*-cert.pub'

################################################################
## GitLab PostgreSQL
################################################################

###! Changing any of these settings requires a restart of postgresql.
###! By default, reconfigure reloads postgresql if it is running. If you
###! change any of these settings, be sure to run `gitlab-ctl restart postgresql`
###! after reconfigure in order for the changes to take effect.
# postgresql['enable'] = true
# postgresql['listen_address'] = nil
# postgresql['port'] = 5432

## Only used when Patroni is enabled. This is the port that PostgreSQL responds to other
## cluster members. This port is used by Patroni to advertize the PostgreSQL connection
## endpoint to the cluster. By default it is the same as postgresql['port'].
# postgresql['connect_port'] = 5432

##! **recommend value is 1/4 of total RAM, up to 14GB.**
# postgresql['shared_buffers'] = "256MB"

### Advanced settings
# postgresql['ha'] = false
# postgresql['dir'] = "/var/opt/gitlab/postgresql"
# postgresql['log_directory'] = "/var/log/gitlab/postgresql"
# postgresql['log_destination'] = nil
# postgresql['logging_collector'] = nil
# postgresql['log_truncate_on_rotation'] = nil
# postgresql['log_rotation_age'] = nil
# postgresql['log_rotation_size'] = nil
##! 'username' affects the system and PostgreSQL user accounts created during installation and cannot be changed
##! on an existing installation. See https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/3606 for more details.
# postgresql['username'] = "gitlab-psql"
# postgresql['group'] = "gitlab-psql"
##! `SQL_USER_PASSWORD_HASH` can be generated using the command `gitlab-ctl pg-password-md5 gitlab`
# postgresql['sql_user_password'] = 'SQL_USER_PASSWORD_HASH'
# postgresql['uid'] = nil
# postgresql['gid'] = nil
# postgresql['shell'] = "/bin/sh"
# postgresql['home'] = "/var/opt/gitlab/postgresql"
# postgresql['user_path'] = "/opt/gitlab/embedded/bin:/opt/gitlab/bin:$PATH"
# postgresql['sql_user'] = "gitlab"
# postgresql['max_connections'] = 400
# postgresql['md5_auth_cidr_addresses'] = []
# postgresql['trust_auth_cidr_addresses'] = []
# postgresql['wal_buffers'] = "-1"
# postgresql['autovacuum_max_workers'] = "3"
# postgresql['autovacuum_freeze_max_age'] = "200000000"
# postgresql['log_statement'] = nil
# postgresql['track_activity_query_size'] = "1024"
# postgresql['shared_preload_libraries'] = nil
# postgresql['dynamic_shared_memory_type'] = nil
# postgresql['hot_standby'] = "off"

### SSL settings
# See https://www.postgresql.org/docs/12/static/runtime-config-connection.html#GUC-SSL-CERT-FILE for more details
# postgresql['ssl'] = 'on'
# postgresql['hostssl'] = false
# postgresql['ssl_ciphers'] = 'HIGH:MEDIUM:+3DES:!aNULL:!SSLv3:!TLSv1'
# postgresql['ssl_cert_file'] = 'server.crt'
# postgresql['ssl_key_file'] = 'server.key'
# postgresql['ssl_ca_file'] = '/opt/gitlab/embedded/ssl/certs/cacert.pem'
# postgresql['ssl_crl_file'] = nil
# postgresql['cert_auth_addresses'] = {
#   'ADDRESS' => {
#     database: 'gitlabhq_production',
#     user: 'gitlab'
#   }
# }

### Replication settings
###! Note, some replication settings do not require a full restart. They are documented below.
# postgresql['wal_level'] = "hot_standby"
# postgresql['wal_log_hints'] = 'off'
# postgresql['max_wal_senders'] = 5
# postgresql['max_replication_slots'] = 0
# postgresql['max_locks_per_transaction'] = 128

# Backup/Archive settings
# postgresql['archive_mode'] = "off"

###! Changing any of these settings only requires a reload of postgresql. You do not need to
###! restart postgresql if you change any of these and run reconfigure.
# postgresql['work_mem'] = "16MB"
# postgresql['maintenance_work_mem'] = "16MB"
# postgresql['checkpoint_timeout'] = "5min"
# postgresql['checkpoint_completion_target'] = 0.9
# postgresql['effective_io_concurrency'] = 1
# postgresql['checkpoint_warning'] = "30s"
# postgresql['effective_cache_size'] = "1MB"
# postgresql['shmmax'] =  17179869184 # or 4294967295
# postgresql['shmall'] =  4194304 # or 1048575
# postgresql['autovacuum'] = "on"
# postgresql['log_autovacuum_min_duration'] = "-1"
# postgresql['autovacuum_naptime'] = "1min"
# postgresql['autovacuum_vacuum_threshold'] = "50"
# postgresql['autovacuum_analyze_threshold'] = "50"
# postgresql['autovacuum_vacuum_scale_factor'] = "0.02"
# postgresql['autovacuum_analyze_scale_factor'] = "0.01"
# postgresql['autovacuum_vacuum_cost_delay'] = "20ms"
# postgresql['autovacuum_vacuum_cost_limit'] = "-1"
# postgresql['statement_timeout'] = "60000"
# postgresql['idle_in_transaction_session_timeout'] = "60000"
# postgresql['log_line_prefix'] = "%a"
# postgresql['max_worker_processes'] = 8
# postgresql['max_parallel_workers_per_gather'] = 0
# postgresql['log_lock_waits'] = 1
# postgresql['deadlock_timeout'] = '5s'
# postgresql['track_io_timing'] = 0
# postgresql['default_statistics_target'] = 1000

### Available in PostgreSQL 9.6 and later
# postgresql['min_wal_size'] = "80MB"
# postgresql['max_wal_size'] = "1GB"

# Backup/Archive settings
# postgresql['archive_command'] = nil
# postgresql['archive_timeout'] = "0"

### Replication settings
# postgresql['sql_replication_user'] = "gitlab_replicator"
# postgresql['sql_replication_password'] = "md5 hash of postgresql password" # You can generate with `gitlab-ctl pg-password-md5 <dbuser>`
# postgresql['wal_keep_segments'] = 10
# postgresql['max_standby_archive_delay'] = "30s"
# postgresql['max_standby_streaming_delay'] = "30s"
# postgresql['synchronous_commit'] = on
# postgresql['synchronous_standby_names'] = ''
# postgresql['hot_standby_feedback'] = 'off'
# postgresql['random_page_cost'] = 2.0
# postgresql['log_temp_files'] = -1
# postgresql['log_checkpoints'] = 'off'
# To add custom entries to pg_hba.conf use the following
# postgresql['custom_pg_hba_entries'] = {
#   APPLICATION: [ # APPLICATION should identify what the settings are used for
#     {
#       type: example,
#       database: example,
#       user: example,
#       cidr: example,
#       method: example,
#       option: example
#     }
#   ]
# }
# See https://www.postgresql.org/docs/12/static/auth-pg-hba-conf.html for an explanation
# of the values

### Version settings
# Set this if you have disabled the bundled PostgreSQL but still want to use the backup rake tasks
# postgresql['version'] = 10


##! Automatically restart PostgreSQL service when version changes.
# postgresql['auto_restart_on_version_change'] = true

################################################################################
## GitLab Redis
##! **Can be disabled if you are using your own Redis instance.**
##! Docs: https://docs.gitlab.com/omnibus/settings/redis.html
################################################################################

# redis['enable'] = true
# redis['ha'] = false
# redis['hz'] = 10
# redis['dir'] = "/var/opt/gitlab/redis"
# redis['log_directory'] = "/var/log/gitlab/redis"
# redis['username'] = "gitlab-redis"
# redis['group'] = "gitlab-redis"
# redis['maxclients'] = "10000"
# redis['maxmemory'] = "0"
# redis['maxmemory_policy'] = "noeviction"
# redis['maxmemory_samples'] = "5"
# redis['stop_writes_on_bgsave_error'] = true
# redis['tcp_backlog'] = 511
# redis['tcp_timeout'] = "60"
# redis['tcp_keepalive'] = "300"
# redis['uid'] = nil
# redis['gid'] = nil

### Redis TLS settings
###! To run Redis over TLS, specify values for the following settings
# redis['tls_port'] = nil
# redis['tls_cert_file'] = nil
# redis['tls_key_file'] = nil

###! Other TLS related optional settings
# redis['tls_dh_params_file'] = nil
# redis['tls_ca_cert_dir'] = '/opt/gitlab/embedded/ssl/certs/'
# redis['tls_ca_cert_file'] = '/opt/gitlab/embedded/ssl/certs/cacert.pem'
# redis['tls_auth_clients'] = 'optional'
# redis['tls_replication'] = nil
# redis['tls_cluster'] = nil
# redis['tls_protocols'] = nil
# redis['tls_ciphers'] = nil
# redis['tls_ciphersuites'] = nil
# redis['tls_prefer_server_ciphers'] = nil
# redis['tls_session_caching'] = nil
# redis['tls_session_cache_size'] = nil
# redis['tls_session_cache_timeout'] = nil

### Disable or obfuscate unnecessary redis command names
### Uncomment and edit this block to add or remove entries.
### See https://docs.gitlab.com/omnibus/settings/redis.html#renamed-commands
### for detailed usage
###
# redis['rename_commands'] = {
#   'KEYS': ''
#}
#

###! **To enable only Redis service in this machine, uncomment
###!   one of the lines below (choose master or replica instance types).**
###! Docs: https://docs.gitlab.com/omnibus/settings/redis.html
###!       https://docs.gitlab.com/ee/administration/high_availability/redis.html
# redis_master_role['enable'] = true
# redis_replica_role['enable'] = true

### Redis TCP support (will disable UNIX socket transport)
# redis['bind'] = '0.0.0.0' # or specify an IP to bind to a single one
# redis['port'] = 6379
# redis['password'] = 'redis-password-goes-here'

### Redis Sentinel support
###! **You need a master replica Redis replication to be able to do failover**
###! **Please read the documentation before enabling it to understand the
###!   caveats:**
###! Docs: https://docs.gitlab.com/ee/administration/high_availability/redis.html

### Replication support
#### Replica Redis instance
# redis['master'] = false # by default this is true

#### Replica and Sentinel shared configuration
####! **Both need to point to the master Redis instance to get replication and
####!   heartbeat monitoring**
# redis['master_name'] = 'gitlab-redis'
# redis['master_ip'] = nil
# redis['master_port'] = 6379

#### Support to run redis replicas in a Docker or NAT environment
####! Docs: https://redis.io/topics/replication#configuring-replication-in-docker-and-nat
# redis['announce_ip'] = nil
# redis['announce_port'] = nil
# redis['announce_ip_from_hostname'] = false

####! **Master password should have the same value defined in
####!   redis['password'] to enable the instance to transition to/from
####!   master/replica in a failover event.**
# redis['master_password'] = 'redis-password-goes-here'

####! Increase these values when your replicas can't catch up with master
# redis['client_output_buffer_limit_normal'] = '0 0 0'
# redis['client_output_buffer_limit_replica'] = '256mb 64mb 60'
# redis['client_output_buffer_limit_pubsub'] = '32mb 8mb 60'

#####! Redis snapshotting frequency
#####! Set to [] to disable
#####! Set to [''] to clear previously set values
# redis['save'] = [ '900 1', '300 10', '60 10000' ]

#####! Redis lazy freeing
#####! Defaults to false
# redis['lazyfree_lazy_eviction'] = true
# redis['lazyfree_lazy_expire'] = true
# redis['lazyfree_lazy_server_del'] = true
# redis['replica_lazy_flush'] = true

#####! Redis threaded I/O
#####! Defaults to disabled
# redis['io_threads'] = 4
# redis['io_threads_do_reads'] = true

################################################################################
## GitLab Web server
##! Docs: https://docs.gitlab.com/omnibus/settings/nginx.html#using-a-non-bundled-web-server
################################################################################

##! When bundled nginx is disabled we need to add the external webserver user to
##! the GitLab webserver group.
# web_server['external_users'] = []
# web_server['username'] = 'gitlab-www'
# web_server['group'] = 'gitlab-www'
# web_server['uid'] = nil
# web_server['gid'] = nil
# web_server['shell'] = '/bin/false'
# web_server['home'] = '/var/opt/gitlab/nginx'

################################################################################
## GitLab NGINX
##! Docs: https://docs.gitlab.com/omnibus/settings/nginx.html
################################################################################

# nginx['enable'] = true
# nginx['client_max_body_size'] = '250m'
# nginx['redirect_http_to_https'] = false
# nginx['redirect_http_to_https_port'] = 80

##! Most root CA's are included by default
# nginx['ssl_client_certificate'] = "/etc/gitlab/ssl/ca.crt"

##! enable/disable 2-way SSL client authentication
# nginx['ssl_verify_client'] = "off"

##! if ssl_verify_client on, verification depth in the client certificates chain
# nginx['ssl_verify_depth'] = "1"

# nginx['ssl_certificate'] = "/etc/gitlab/ssl/#{node['fqdn']}.crt"
# nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/#{node['fqdn']}.key"
# nginx['ssl_ciphers'] = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
# nginx['ssl_prefer_server_ciphers'] = "off"

##! **Recommended by: https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html
##!                   https://cipherli.st/**
# nginx['ssl_protocols'] = "TLSv1.2 TLSv1.3"

##! **Recommended in: https://nginx.org/en/docs/http/ngx_http_ssl_module.html**
# nginx['ssl_session_cache'] = "shared:SSL:10m"

##! **Recommended in: https://ssl-config.mozilla.org/#server=nginx&version=1.17.7&config=intermediate&openssl=1.1.1d&ocsp=false&guideline=5.6**
# nginx['ssl_session_tickets'] = "off"

##! **Default according to https://nginx.org/en/docs/http/ngx_http_ssl_module.html**
# nginx['ssl_session_timeout'] = "1d"

# nginx['ssl_dhparam'] = nil # Path to dhparams.pem, eg. /etc/gitlab/ssl/dhparams.pem
# nginx['ssl_password_file'] = nil # Path to file with passphrases for ssl certificate secret keys
# nginx['listen_addresses'] = ['*', '[::]']

##! **Defaults to forcing web browsers to always communicate using only HTTPS**
##! Docs: https://docs.gitlab.com/omnibus/settings/nginx.html#setting-http-strict-transport-security
# nginx['hsts_max_age'] = 63072000
# nginx['hsts_include_subdomains'] = false

##! Defaults to stripping path information when making cross-origin requests
# nginx['referrer_policy'] = 'strict-origin-when-cross-origin'

##! **Docs: http://nginx.org/en/docs/http/ngx_http_gzip_module.html**
# nginx['gzip_enabled'] = true

##! **Override only if you use a reverse proxy**
##! Docs: https://docs.gitlab.com/omnibus/settings/nginx.html#setting-the-nginx-listen-port
nginx['listen_port'] = 80
nginx['listen_https'] = false

##! **Override only if you use a reverse proxy with proxy protocol enabled**
##! Docs: https://docs.gitlab.com/omnibus/settings/nginx.html#configuring-proxy-protocol
# nginx['proxy_protocol'] = false

# nginx['custom_gitlab_server_config'] = "location ^~ /foo-namespace/bar-project/raw/ {\n deny all;\n}\n"
# nginx['custom_nginx_config'] = "include /etc/nginx/conf.d/example.conf;"
# nginx['proxy_read_timeout'] = 3600
# nginx['proxy_connect_timeout'] = 300
# nginx['proxy_set_headers'] = {
#  "Host" => "$http_host_with_default",
#  "X-Real-IP" => "$remote_addr",
#  "X-Forwarded-For" => "$proxy_add_x_forwarded_for",
#  "X-Forwarded-Proto" => "https",
#  "X-Forwarded-Ssl" => "on",
#  "Upgrade" => "$http_upgrade",
#  "Connection" => "$connection_upgrade"
# }
# nginx['proxy_cache_path'] = 'proxy_cache keys_zone=gitlab:10m max_size=1g levels=1:2'
# nginx['proxy_cache'] = 'gitlab'
# nginx['proxy_custom_buffer_size'] = '4k'
# nginx['http2_enabled'] = true
# nginx['real_ip_trusted_addresses'] = []
# nginx['real_ip_header'] = nil
# nginx['real_ip_recursive'] = nil
# nginx['custom_error_pages'] = {
#   '404' => {
#     'title' => 'Example title',
#     'header' => 'Example header',
#     'message' => 'Example message'
#   }
# }

### Advanced settings
# nginx['dir'] = "/var/opt/gitlab/nginx"
# nginx['log_directory'] = "/var/log/gitlab/nginx"
# nginx['error_log_level'] = "error"
# nginx['worker_processes'] = 4
# nginx['worker_connections'] = 10240
# nginx['log_format'] = '$remote_addr - $remote_user [$time_local] "$request_method $filtered_request_uri $server_protocol" $status $body_bytes_sent "$filtered_http_referer" "$http_user_agent" $gzip_ratio'
# nginx['sendfile'] = 'on'
# nginx['tcp_nopush'] = 'on'
# nginx['tcp_nodelay'] = 'on'
# nginx['hide_server_tokens'] = 'off'
# nginx['gzip_http_version'] = "1.0"
# nginx['gzip_comp_level'] = "2"
# nginx['gzip_proxied'] = "any"
# nginx['gzip_types'] = [ "text/plain", "text/css", "application/x-javascript", "text/xml", "application/xml", "application/xml+rss", "text/javascript", "application/json" ]
# nginx['keepalive_timeout'] = 65
# nginx['keepalive_time'] = '1h'
# nginx['cache_max_size'] = '5000m'
# nginx['server_names_hash_bucket_size'] = 64
##! These paths have proxy_request_buffering disabled
# nginx['request_buffering_off_path_regex'] = "/api/v\\d/jobs/\\d+/artifacts$|/import/gitlab_project$|\\.git/git-receive-pack$|\\.git/gitlab-lfs/objects|\\.git/info/lfs/objects/batch$"

### Nginx status
# nginx['status'] = {
#  "enable" => true,
#  "listen_addresses" => ["127.0.0.1"],
#  "fqdn" => "dev.example.com",
#  "port" => 9999,
#  "vts_enable" => true,
#  "options" => {
#    "server_tokens" => "off", # Don't show the version of NGINX
#    "access_log" => "off", # Disable logs for stats
#    "allow" => "127.0.0.1", # Only allow access from localhost
#    "deny" => "all" # Deny access to anyone else
#  }
# }

##! Service name used to register Nginx as a Consul service
# nginx['consul_service_name'] = 'nginx'
##! Semantic metadata used when registering NGINX as a Consul service
# nginx['consul_service_meta'] = {}

################################################################################
## GitLab Logging
##! Docs: https://docs.gitlab.com/omnibus/settings/logs.html
################################################################################

# logging['svlogd_size'] = 200 * 1024 * 1024 # rotate after 200 MB of log data
# logging['svlogd_num'] = 30 # keep 30 rotated log files
# logging['svlogd_timeout'] = 24 * 60 * 60 # rotate after 24 hours
# logging['svlogd_filter'] = "gzip" # compress logs with gzip
# logging['svlogd_udp'] = nil # transmit log messages via UDP
# logging['svlogd_prefix'] = nil # custom prefix for log messages
# logging['logrotate_frequency'] = "daily" # rotate logs daily
# logging['logrotate_maxsize'] = nil # rotate logs when they grow bigger than size bytes even before the specified time interval (daily, weekly, monthly, or yearly)
# logging['logrotate_size'] = nil # do not rotate by size by default
# logging['logrotate_rotate'] = 30 # keep 30 rotated logs
# logging['logrotate_compress'] = "compress" # see 'man logrotate'
# logging['logrotate_method'] = "copytruncate" # see 'man logrotate'
# logging['logrotate_postrotate'] = nil # no postrotate command by default
# logging['logrotate_dateformat'] = nil # use date extensions for rotated files rather than numbers e.g. a value of "-%Y-%m-%d" would give rotated files like production.log-2016-03-09.gz

### UDP log forwarding
##! Docs: http://docs.gitlab.com/omnibus/settings/logs.html#udp-log-forwarding

##! remote host to ship log messages to via UDP
# logging['udp_log_shipping_host'] = nil

##! override the hostname used when logs are shipped via UDP,
##  by default the system hostname will be used.
# logging['udp_log_shipping_hostname'] = nil

##! remote port to ship log messages to via UDP
# logging['udp_log_shipping_port'] = 514

################################################################################
## Logrotate
##! Docs: https://docs.gitlab.com/omnibus/settings/logs.html#logrotate
##! You can disable built in logrotate feature.
################################################################################
# logrotate['enable'] = true
# logrotate['log_directory'] = "/var/log/gitlab/logrotate"

################################################################################
## Users and groups accounts
##! Disable management of users and groups accounts.
##! **Set only if creating accounts manually**
##! Docs: https://docs.gitlab.com/omnibus/settings/configuration.html#disable-user-and-group-account-management
################################################################################

# manage_accounts['enable'] = true

################################################################################
## Storage directories
##! Disable managing storage directories
##! Docs: https://docs.gitlab.com/omnibus/settings/configuration.html#disable-storage-directories-management
################################################################################

##! **Set only if the select directories are created manually**
# manage_storage_directories['enable'] = false
# manage_storage_directories['manage_etc'] = false

################################################################################
## Runtime directory
##! Docs: https://docs.gitlab.com//omnibus/settings/configuration.html#configuring-runtime-directory
################################################################################

# runtime_dir '/run'

################################################################################
## Git
##! Advanced setting for configuring git system settings for omnibus-gitlab
##! internal git
################################################################################

##! The format of the Omnibus gitconfig is:
##! { "section" => ["subsection = value"] }
##! For example:
##! { "pack" => ["threads = 1"] }
##! For multiple options under one header use array of comma separated values,
##! eg.:
##! { "receive" => ["fsckObjects = true"], "alias" => ["st = status", "co = checkout"] }
# omnibus_gitconfig['system'] = {}

################################################################################
## GitLab Pages
##! Docs: https://docs.gitlab.com/ee/administration/pages/
################################################################################

##! Define to enable GitLab Pages
# pages_external_url "http://pages.example.com/"
# gitlab_pages['enable'] = false

##! Configure to expose GitLab Pages on external IP address, serving the HTTP
# gitlab_pages['external_http'] = []

##! Configure to expose GitLab Pages on external IP address, serving the HTTPS
# gitlab_pages['external_https'] = []

##! Configure to expose GitLab Pages on external IP address, serving the HTTPS over PROXYv2
# gitlab_pages['external_https_proxyv2'] = []

##! Configure cert when using external IP address
# gitlab_pages['cert'] = "/etc/gitlab/ssl/#{Gitlab['gitlab_pages']['domain']}.crt"
# gitlab_pages['cert_key'] = "/etc/gitlab/ssl/#{Gitlab['gitlab_pages']['domain']}.key"

##! Configure to use the default list of cipher suites
# gitlab_pages['insecure_ciphers'] = false

##! Configure to enable health check endpoint on GitLab Pages
# gitlab_pages['status_uri'] = "/@status"

##! Tune the maximum number of concurrent connections GitLab Pages will handle.
##! Default to 0 for unlimited connections.
# gitlab_pages['max_connections'] = 0

##! Configure the maximum length of URIs accepted by GitLab Pages
##! By default is limited for security reasons. Set 0 for unlimited
# gitlab_pages['max_uri_length'] = 1024

##! Setting the propagate_correlation_id to true allows installations behind a reverse proxy
##! generate and set a correlation ID to requests sent to GitLab Pages. If a reverse proxy
##! sets the header value X-Request-ID, the value will be propagated in the request chain.
# gitlab_pages['propagate_correlation_id'] = false

##! Configure to use JSON structured logging in GitLab Pages
# gitlab_pages['log_format'] = "json"

##! Configure verbose logging for GitLab Pages
# gitlab_pages['log_verbose'] = false

##! Error Reporting and Logging with Sentry
# gitlab_pages['sentry_enabled'] = false
# gitlab_pages['sentry_dsn'] = 'https://<key>@sentry.io/<project>'
# gitlab_pages['sentry_environment'] = 'production'

##! Listen for requests forwarded by reverse proxy
# gitlab_pages['listen_proxy'] = "localhost:8090"

# gitlab_pages['redirect_http'] = true
# gitlab_pages['use_http2'] = true
# gitlab_pages['dir'] = "/var/opt/gitlab/gitlab-pages"
# gitlab_pages['log_directory'] = "/var/log/gitlab/gitlab-pages"

# gitlab_pages['artifacts_server'] = true
# gitlab_pages['artifacts_server_url'] = nil # Defaults to external_url + '/api/v4'
# gitlab_pages['artifacts_server_timeout'] = 10

##! Prometheus metrics for Pages docs: https://gitlab.com/gitlab-org/gitlab-pages/#enable-prometheus-metrics
# gitlab_pages['metrics_address'] = ":9235"

##! Specifies the minimum TLS version ("tls1.2" or "tls1.3")
# gitlab_pages['tls_min_version'] = "tls1.2"

##! Specifies the maximum TLS version ("tls1.2" or "tls1.3")
# gitlab_pages['tls_max_version'] = "tls1.3"

##! Pages access control
# gitlab_pages['access_control'] = false
# gitlab_pages['gitlab_id'] = nil # Automatically generated if not present
# gitlab_pages['gitlab_secret'] = nil # Generated if not present
# gitlab_pages['auth_redirect_uri'] = nil # Defaults to projects subdomain of pages_external_url and + '/auth'
# gitlab_pages['gitlab_server'] = nil # Defaults to external_url
# gitlab_pages['internal_gitlab_server'] = nil # Defaults to gitlab_server, can be changed to internal load balancer
# gitlab_pages['auth_secret'] = nil # Generated if not present
# gitlab_pages['auth_scope'] = nil # Defaults to api, can be changed to read_api to increase security
# gitlab_pages['auth_cookie_session_timeout'] = "10m" # Authentication cookie session timeout (truncated to seconds). A zero value means the cookie will be deleted after the browser session ends

##! GitLab Pages Server Shutdown Timeout
##! Duration ("30s" for 30 seconds)
# gitlab_pages['server_shutdown_timeout'] = "30s"

##! GitLab API HTTP client connection timeout
# gitlab_pages['gitlab_client_http_timeout'] = "10s"

##! GitLab API JWT Token expiry time
# gitlab_pages['gitlab_client_jwt_expiry'] = "30s"

##! Advanced settings for API-based configuration for GitLab Pages.
##! The recommended default values are set inside GitLab Pages.
##! Should be changed only if absolutely needed.

##! The maximum time a domain's configuration is stored in the cache.
# gitlab_pages['gitlab_cache_expiry'] = "600s"
##! The interval at which a domain's configuration is set to be due to refresh (default: 60s).
# gitlab_pages['gitlab_cache_refresh'] = "60s"
##! The interval at which expired items are removed from the cache (default: 60s).
# gitlab_pages['gitlab_cache_cleanup'] = "60s"
##! The maximum time to wait for a response from the GitLab API per request.
# gitlab_pages['gitlab_retrieval_timeout'] = "30s"
##! The interval to wait before retrying to resolve a domain's configuration via the GitLab API.
# gitlab_pages['gitlab_retrieval_interval'] = "1s"
##! The maximum number of times to retry to resolve a domain's configuration via the API
# gitlab_pages['gitlab_retrieval_retries'] = 3

##! Define custom gitlab-pages HTTP headers for the whole instance
# gitlab_pages['headers'] = []

##! Shared secret used for authentication between Pages and GitLab
# gitlab_pages['api_secret_key'] = nil # Will be generated if not set. Base64 encoded and exactly 32 bytes long.

##! Advanced settings for serving GitLab Pages from zip archives.
##! The recommended default values are set inside GitLab Pages.
##! Should be changed only if absolutely needed.

##! The maximum time an archive will be cached in memory.
# gitlab_pages['zip_cache_expiration'] = "60s"
##! Zip archive cache cleaning interval.
# gitlab_pages['zip_cache_cleanup'] = "30s"
##! The interval to refresh a cache archive if accessed before expiring.
# gitlab_pages['zip_cache_refresh'] = "30s"
##! The maximum amount of time it takes to open a zip archive from the file system or object storage.
# gitlab_pages['zip_open_timeout'] = "30s"
##! Zip HTTP Client timeout
# gitlab_pages['zip_http_client_timeout'] = "30m"

##! ReadTimeout is the maximum duration for reading the entire request, including the body. A zero or negative value means there will be no timeout.
# gitlab_pages['server_read_timeout'] = "5s"
##! ReadHeaderTimeout is the amount of time allowed to read request headers. A zero or negative value means there will be no timeout.
# gitlab_pages['server_read_header_timeout'] = "1s"
##! WriteTimeout is the maximum duration before timing out writes of the response. A zero or negative value means there will be no timeout.
# gitlab_pages['server_write_timeout'] = "5m"
##! KeepAlive specifies the keep-alive period for network connections accepted by this listener. If zero, keep-alives are enabled if supported by the protocol and operating system. If negative, keep-alives are disabled.
# gitlab_pages['server_keep_alive'] = "15s"

##! Enable serving content from disk instead of Object Storage
# gitlab_pages['enable_disk'] = nil

##! Rate-limiting options below work in report-only mode:
##! they only count rejected requests, but don't reject them
##! enable `FF_ENABLE_RATE_LIMITER=true` environment variable to
##! reject requests.

##! Rate limits as described in https://docs.gitlab.com/ee/administration/pages/#rate-limits

##! Rate limit HTTP requests per second from a single IP, 0 means is disabled
# gitlab_pages['rate_limit_source_ip'] = 50.0
##! Rate limit HTTP requests from a single IP, maximum burst allowed per second
# gitlab_pages['rate_limit_source_ip_burst'] = 600
##! Rate limit HTTP requests per second to a single domain, 0 means is disabled
# gitlab_pages['rate_limit_domain'] = 0
##! Rate limit HTTP requests to a single domain, maximum burst allowed per second
# gitlab_pages['rate_limit_domain_burst'] = 10000

##! Rate limit new TLS connections per second from a single IP, 0 means is disabled
# gitlab_pages['rate_limit_tls_source_ip'] = 50.0
##! Rate limit new TLS connections from a single IP, maximum burst allowed per second
# gitlab_pages['rate_limit_tls_source_ip_burst'] = 600
##!Rate limit new TLS connections per second from to a single domain, 0 means is disabled
# gitlab_pages['rate_limit_tls_domain'] = 0
##! Rate limit new TLS connections to a single domain, maximum burst allowed per second
# gitlab_pages['rate_limit_tls_domain_burst'] = 10000

##! The maximum size of the _redirects file, in bytes
# gitlab_pages['redirects_max_config_size'] = 65536
##! The maximum number of path segments allowed in _redirects rules URLs
# gitlab_pages['redirects_max_path_segments'] = 25
##! The maximum number of rules allowed in _redirects
# gitlab_pages['redirects_max_rule_count'] = 1000

# gitlab_pages['env_directory'] = "/opt/gitlab/etc/gitlab-pages/env"
# gitlab_pages['env'] = {
#   'SSL_CERT_DIR' => "#{node['package']['install-dir']}/embedded/ssl/certs/"
# }

################################################################################
## GitLab Pages NGINX
################################################################################

# All the settings defined in the "GitLab Nginx" section are also available in
# this "GitLab Pages NGINX" section, using the key `pages_nginx`.  However,
# those settings should be explicitly set. That is, settings given as
# `nginx['some_setting']` WILL NOT be automatically replicated as
# `pages_nginx['some_setting']` and should be set separately.

# Below you can find settings that are exclusive to "GitLab Pages NGINX"
# pages_nginx['enable'] = true

# gitlab_rails['pages_path'] = "/var/opt/gitlab/gitlab-rails/shared/pages"

################################################################################
## GitLab CI
##! Docs: https://docs.gitlab.com/ee/ci/quick_start/
################################################################################

# gitlab_ci['gitlab_ci_all_broken_builds'] = true
# gitlab_ci['gitlab_ci_add_pusher'] = true
# gitlab_ci['builds_directory'] = '/var/opt/gitlab/gitlab-ci/builds'

################################################################################
## GitLab Kubernetes Agent Server
##! Docs: https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/blob/master/README.md
################################################################################

##! Settings used by the GitLab application
# gitlab_rails['gitlab_kas_enabled'] = true
# gitlab_rails['gitlab_kas_external_url'] = 'ws://gitlab.example.com/-/kubernetes-agent/'
# gitlab_rails['gitlab_kas_internal_url'] = 'grpc://localhost:8153'
# gitlab_rails['gitlab_kas_external_k8s_proxy_url'] = 'https://gitlab.example.com/-/kubernetes-agent/k8s-proxy/'

##! Enable GitLab KAS
# gitlab_kas['enable'] = true

##! Agent configuration for GitLab KAS
# gitlab_kas['agent_configuration_poll_period'] = 20
# gitlab_kas['agent_gitops_poll_period'] = 20
# gitlab_kas['agent_gitops_project_info_cache_ttl'] = 300
# gitlab_kas['agent_gitops_project_info_cache_error_ttl'] = 60
# gitlab_kas['agent_info_cache_ttl'] = 300
# gitlab_kas['agent_info_cache_error_ttl'] = 60

##! Shared secret used for authentication between KAS and GitLab
# gitlab_kas['api_secret_key'] = nil # Will be generated if not set. Base64 encoded and exactly 32 bytes long.

##! Shared secret used for authentication between different KAS instances in a multi-node setup
# gitlab_kas['private_api_secret_key'] = nil # Will be generated if not set. Base64 encoded and exactly 32 bytes long.

##! Listen configuration for GitLab KAS
# gitlab_kas['listen_address'] = 'localhost:8150'
# gitlab_kas['listen_network'] = 'tcp'
# gitlab_kas['listen_websocket'] = true
# gitlab_kas['certificate_file'] = "/path/to/certificate.pem"
# gitlab_kas['key_file'] = "/path/to/key.pem"
# gitlab_kas['observability_listen_network'] = 'tcp'
# gitlab_kas['observability_listen_address'] = 'localhost:8151'
# gitlab_kas['internal_api_listen_network'] = 'tcp'
# gitlab_kas['internal_api_listen_address'] = 'localhost:8153'
# gitlab_kas['internal_api_certificate_file'] = "/path/to/certificate.pem"
# gitlab_kas['internal_api_key_file'] = "/path/to/key.pem"
# gitlab_kas['kubernetes_api_listen_address'] = 'localhost:8154'
# gitlab_kas['kubernetes_api_certificate_file'] = "/path/to/certificate.pem"
# gitlab_kas['kubernetes_api_key_file'] = "/path/to/key.pem"
# gitlab_kas['private_api_listen_network'] = 'tcp'
# gitlab_kas['private_api_listen_address'] = 'localhost:8155'
# gitlab_kas['private_api_certificate_file'] = "/path/to/certificate.pem"
# gitlab_kas['private_api_key_file'] = "/path/to/key.pem"

##! Metrics configuration for GitLab KAS
# gitlab_kas['metrics_usage_reporting_period'] = 60

##! Log configuration for GitLab KAS
# gitlab_kas['log_level'] = 'info'

##! Environment variables for GitLab KAS
# gitlab_kas['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/",
#   # In a multi-node setup, this address MUST be reachable from other KAS instances. In a single-node setup, it can be on localhost for simplicity
#   'OWN_PRIVATE_API_URL' => 'grpc://localhost:8155'
# }

##! Error Reporting and Logging with Sentry
# gitlab_kas['sentry_dsn'] = 'https://<key>@sentry.io/<project>'
# gitlab_kas['sentry_environment'] = 'production'

##! Directories for GitLab KAS
# gitlab_kas['dir'] = '/var/opt/gitlab/gitlab-kas'
# gitlab_kas['log_directory'] = '/var/log/gitlab/gitlab-kas'
# gitlab_kas['env_directory'] = '/opt/gitlab/etc/gitlab-kas/env'

################################################################################
## GitLab Suggested Reviewers (EE Only)
##! Docs: https://docs.gitlab.com/ee/user/project/merge_requests/reviews/#suggested-reviewers
################################################################################

##! Shared secret used for authentication between Suggested Reviewers and GitLab
# suggested_reviewers['api_secret_key'] = nil # Will be generated if not set. Base64 encoded and exactly 32 bytes long.

################################################################################
## GitLab Mattermost
##! Docs: https://docs.gitlab.com/omnibus/gitlab-mattermost
################################################################################

# mattermost_external_url 'http://mattermost.example.com'

# mattermost['enable'] = false
# mattermost['username'] = 'mattermost'
# mattermost['group'] = 'mattermost'
# mattermost['uid'] = nil
# mattermost['gid'] = nil
# mattermost['home'] = '/var/opt/gitlab/mattermost'
# mattermost['database_name'] = 'mattermost_production'
# mattermost['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }
# mattermost['service_address'] = "127.0.0.1"
# mattermost['service_port'] = "8065"
# mattermost['service_site_url'] = nil
# mattermost['service_allowed_untrusted_internal_connections'] = ""
# mattermost['service_enable_api_team_deletion'] = true
# mattermost['team_site_name'] = "GitLab Mattermost"
# mattermost['sql_driver_name'] = 'mysql'
# mattermost['sql_data_source'] = "mmuser:mostest@tcp(dockerhost:3306)/mattermost_test?charset=utf8mb4,utf8"
# mattermost['log_file_directory'] = '/var/log/gitlab/mattermost/'
# mattermost['gitlab_enable'] = false
# mattermost['gitlab_id'] = "12345656"
# mattermost['gitlab_secret'] = "123456789"
# mattermost['gitlab_scope'] = ""
# mattermost['gitlab_auth_endpoint'] = "http://gitlab.example.com/oauth/authorize"
# mattermost['gitlab_token_endpoint'] = "http://gitlab.example.com/oauth/token"
# mattermost['gitlab_user_api_endpoint'] = "http://gitlab.example.com/api/v4/user"
# mattermost['file_directory'] = "/var/opt/gitlab/mattermost/data"
# mattermost['plugin_directory'] = "/var/opt/gitlab/mattermost/plugins"
# mattermost['plugin_client_directory'] = "/var/opt/gitlab/mattermost/client-plugins"

################################################################################
## Mattermost NGINX
################################################################################

# All the settings defined in the "GitLab Nginx" section are also available in
# this "Mattermost NGINX" section, using the key `mattermost_nginx`.  However,
# those settings should be explicitly set. That is, settings given as
# `nginx['some_setting']` WILL NOT be automatically replicated as
# `mattermost_nginx['some_setting']` and should be set separately.

# Below you can find settings that are exclusive to "Mattermost NGINX"
# mattermost_nginx['enable'] = false

# mattermost_nginx['custom_gitlab_mattermost_server_config'] = "location ^~ /foo-namespace/bar-project/raw/ {\n deny all;\n}\n"
# mattermost_nginx['proxy_set_headers'] = {
#   "Host" => "$http_host",
#   "X-Real-IP" => "$remote_addr",
#   "X-Forwarded-For" => "$proxy_add_x_forwarded_for",
#   "X-Frame-Options" => "SAMEORIGIN",
#   "X-Forwarded-Proto" => "https",
#   "X-Forwarded-Ssl" => "on",
#   "Upgrade" => "$http_upgrade",
#   "Connection" => "$connection_upgrade"
# }


################################################################################
## Registry NGINX
################################################################################

# All the settings defined in the "GitLab Nginx" section are also available in
# this "Registry NGINX" section, using the key `registry_nginx`.  However, those
# settings should be explicitly set. That is, settings given as
# `nginx['some_setting']` WILL NOT be automatically replicated as
# `registry_nginx['some_setting']` and should be set separately.

# Below you can find settings that are exclusive to "Registry NGINX"
registry_nginx['enable'] = false
registry_nginx['listen_https'] = false

# registry_nginx['proxy_set_headers'] = {
#  "Host" => "$http_host",
#  "X-Real-IP" => "$remote_addr",
#  "X-Forwarded-For" => "$proxy_add_x_forwarded_for",
#  "X-Forwarded-Proto" => "https",
#  "X-Forwarded-Ssl" => "on"
# }

# When the registry is automatically enabled using the same domain as `external_url`,
# it listens on this port
# registry_nginx['listen_port'] = 5050

################################################################################
## Prometheus
##! Docs: https://docs.gitlab.com/ee/administration/monitoring/prometheus/
################################################################################

###! **To enable only Monitoring service in this machine, uncomment
###!   the line below.**
###! Docs: https://docs.gitlab.com/ee/administration/high_availability
# monitoring_role['enable'] = true

# prometheus['enable'] = true
# prometheus['monitor_kubernetes'] = true
# prometheus['username'] = 'gitlab-prometheus'
# prometheus['group'] = 'gitlab-prometheus'
# prometheus['uid'] = nil
# prometheus['gid'] = nil
# prometheus['shell'] = '/bin/sh'
# prometheus['home'] = '/var/opt/gitlab/prometheus'
# prometheus['log_directory'] = '/var/log/gitlab/prometheus'
# prometheus['rules_files'] = ['/var/opt/gitlab/prometheus/rules/*.rules']
# prometheus['scrape_interval'] = 15
# prometheus['scrape_timeout'] = 15
# prometheus['external_labels'] = { }
# prometheus['env_directory'] = '/opt/gitlab/etc/prometheus/env'
# prometheus['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }
#
### Custom scrape configs
#
# Prometheus can scrape additional jobs via scrape_configs.  The default automatically
# includes all of the exporters supported by the omnibus config.
#
# See: https://prometheus.io/docs/operating/configuration/#<scrape_config>
#
# Example:
#
# prometheus['scrape_configs'] = [
#   {
#     'job_name': 'example',
#     'static_configs' => [
#       'targets' => ['hostname:port'],
#     ],
#   },
# ]
#
### Custom alertmanager config
#
# To configure external alertmanagers, create an alertmanager config.
#
# See: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alertmanager_config
#
# prometheus['alertmanagers'] = [
#   {
#     'static_configs' => [
#       {
#         'targets' => [
#           'hostname:port'
#         ]
#       }
#     ]
#   }
# ]
#
### Custom Prometheus flags
#
# prometheus['flags'] = {
#   'storage.tsdb.path' => "/var/opt/gitlab/prometheus/data",
#   'storage.tsdb.retention.time' => "15d",
#   'config.file' => "/var/opt/gitlab/prometheus/prometheus.yml"
# }

##! Advanced settings. Should be changed only if absolutely needed.
# prometheus['listen_address'] = 'localhost:9090'
#

##! Service name used to register Prometheus as a Consul service
# prometheus['consul_service_name'] = 'prometheus'
##! Semantic metadata used when registering Prometheus as a Consul service
# prometheus['consul_service_meta'] = {}

################################################################################
###! **Only needed if Prometheus and Rails are not on the same server.**
### For example, in a multi-node architecture, Prometheus will be installed on the monitoring node, while Rails will be on the Rails node.
### https://docs.gitlab.com/ee/administration/monitoring/prometheus/index.html#using-an-external-prometheus-server
### This value should be the address at which Prometheus is available to a GitLab Rails(Puma, Sidekiq) node.
################################################################################
# gitlab_rails['prometheus_address'] = 'your.prom:9090'

################################################################################
## Prometheus Alertmanager
################################################################################

# alertmanager['enable'] = true
# alertmanager['home'] = '/var/opt/gitlab/alertmanager'
# alertmanager['log_directory'] = '/var/log/gitlab/alertmanager'
# alertmanager['admin_email'] = 'admin@example.com'
# alertmanager['flags'] = {
#   'web.listen-address' => "localhost:9093",
#   'storage.path' => "/var/opt/gitlab/alertmanager/data",
#   'config.file' => "/var/opt/gitlab/alertmanager/alertmanager.yml"
# }
# alertmanager['env_directory'] = '/opt/gitlab/etc/alertmanager/env'
# alertmanager['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }

##! Advanced settings. Should be changed only if absolutely needed.
# alertmanager['listen_address'] = 'localhost:9093'
# alertmanager['global'] = {}

################################################################################
## Prometheus Node Exporter
##! Docs: https://docs.gitlab.com/ee/administration/monitoring/prometheus/node_exporter.html
################################################################################

# node_exporter['enable'] = true
# node_exporter['home'] = '/var/opt/gitlab/node-exporter'
# node_exporter['log_directory'] = '/var/log/gitlab/node-exporter'
# node_exporter['flags'] = {
#   'collector.textfile.directory' => "/var/opt/gitlab/node-exporter/textfile_collector"
# }
# node_exporter['env_directory'] = '/opt/gitlab/etc/node-exporter/env'
# node_exporter['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }

##! Advanced settings. Should be changed only if absolutely needed.
# node_exporter['listen_address'] = 'localhost:9100'

##! Service name used to register Node Exporter as a Consul service
# node_exporter['consul_service_name'] = 'node-exporter'
##! Semantic metadata used when registering Node Exporter as a Consul service
# node_exporter['consul_service_meta'] = {}

################################################################################
## Prometheus Redis exporter
##! Docs: https://docs.gitlab.com/ee/administration/monitoring/prometheus/redis_exporter.html
################################################################################

# redis_exporter['enable'] = true
# redis_exporter['log_directory'] = '/var/log/gitlab/redis-exporter'
# redis_exporter['flags'] = {
#   'redis.addr' => "unix:///var/opt/gitlab/redis/redis.socket",
# }
# redis_exporter['env_directory'] = '/opt/gitlab/etc/redis-exporter/env'
# redis_exporter['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }

##! Advanced settings. Should be changed only if absolutely needed.
# redis_exporter['listen_address'] = 'localhost:9121'

##! Service name used to register Redis Exporter as a Consul service
# redis_exporter['consul_service_name'] = 'redis-exporter'
##! Semantic metadata used when registering Redis Exporter as a Consul service
# redis_exporter['consul_service_meta'] = {}

################################################################################
## Prometheus Postgres exporter
##! Docs: https://docs.gitlab.com/ee/administration/monitoring/prometheus/postgres_exporter.html
################################################################################

# postgres_exporter['enable'] = true
# postgres_exporter['home'] = '/var/opt/gitlab/postgres-exporter'
# postgres_exporter['log_directory'] = '/var/log/gitlab/postgres-exporter'
# postgres_exporter['flags'] = {}
# postgres_exporter['listen_address'] = 'localhost:9187'
# postgres_exporter['env_directory'] = '/opt/gitlab/etc/postgres-exporter/env'
# postgres_exporter['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }
# postgres_exporter['sslmode'] = nil
# postgres_exporter['per_table_stats'] = false

##! Service name used to register Postgres Exporter as a Consul service
# postgres_exporter['consul_service_name'] = 'postgres-exporter'
##! Semantic metadata used when registering Postgres Exporter as a Consul service
# postgres_exporter['consul_service_meta'] = {}

################################################################################
## Prometheus PgBouncer exporter (EE only)
##! Docs: https://docs.gitlab.com/ee/administration/monitoring/prometheus/pgbouncer_exporter.html
################################################################################

# pgbouncer_exporter['enable'] = false
# pgbouncer_exporter['log_directory'] = "/var/log/gitlab/pgbouncer-exporter"
# pgbouncer_exporter['listen_address'] = 'localhost:9188'
# pgbouncer_exporter['env_directory'] = '/opt/gitlab/etc/pgbouncer-exporter/env'
# pgbouncer_exporter['env'] = {
#   'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
# }

################################################################################
## Prometheus Gitlab exporter
##! Docs: https://docs.gitlab.com/ee/administration/monitoring/prometheus/gitlab_exporter.html
################################################################################


# gitlab_exporter['enable'] = true
# gitlab_exporter['log_directory'] = "/var/log/gitlab/gitlab-exporter"
# gitlab_exporter['home'] = "/var/opt/gitlab/gitlab-exporter"

##! Advanced settings. Should be changed only if absolutely needed.
# gitlab_exporter['server_name'] = 'webrick'
# gitlab_exporter['listen_address'] = 'localhost'
# gitlab_exporter['listen_port'] = '9168'

##! TLS settings.
# gitlab_exporter['tls_enabled'] = false
# gitlab_exporter['tls_cert_path'] = '/etc/gitlab/ssl/gitlab-exporter.crt'
# gitlab_exporter['tls_key_path'] = '/etc/gitlab/ssl/gitlab-exporter.key'

##! Prometheus scrape related configs
# gitlab_exporter['prometheus_scrape_scheme'] = 'http'
# gitlab_exporter['prometheus_scrape_tls_server_name'] = 'localhost'
# gitlab_exporter['prometheus_scrape_tls_skip_verification'] = false

##! Manage gitlab-exporter sidekiq probes. false by default when Sentinels are
##! found.
# gitlab_exporter['probe_sidekiq'] = true

##! Manage gitlab-exporter elasticsearch probes. Add authorization header if security
##! is enabled.
# gitlab_exporter['probe_elasticsearch'] = false
# gitlab_exporter['elasticsearch_url'] = 'http://localhost:9200'
# gitlab_exporter['elasticsearch_authorization'] = 'Basic <yourbase64encodedcredentials>'

##! Service name used to register GitLab Exporter as a Consul service
# gitlab_exporter['consul_service_name'] = 'gitlab-exporter'
##! Semantic metadata used when registering GitLab Exporter as a Consul service
# gitlab_exporter['consul_service_meta'] = {}

# To completely disable prometheus, and all of it's exporters, set to false
# prometheus_monitoring['enable'] = true

################################################################################
## Grafana Dashboards
##! Docs: https://docs.gitlab.com/ee/administration/monitoring/prometheus/#prometheus-as-a-grafana-data-source
################################################################################

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
