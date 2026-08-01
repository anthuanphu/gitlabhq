# GitLab Security Addon (GSA)

**Enterprise-grade security layer for GitLab** — bảo mật tuyệt đối mã nguồn.

## Giới thiệu

GitLab Security Addon là một addon bảo mật cho GitLab, cho phép admin kiểm soát tuyệt đối việc truy cập mã nguồn. Addon này được thiết kế để **không can thiệp vào mã nguồn lõi** của GitLab, cho phép bạn vẫn nhận được các bản cập nhật từ upstream.

## Tính năng chính

### 🔒 Kiểm soát truy cập mã nguồn
- **Chặn Clone**: Ngăn chặn `git clone`, `git pull`, `git fetch`
- **Chặn Download**: Ngăn tải mã nguồn dạng zip/tar
- **Chặn Fork**: Ngăn fork dự án sang namespace khác
- **Chặn Share**: Ngăn chia sẻ dự án với người dùng/nhóm bên ngoài

### 🚫 Chặn kết nối IDE
- **Chặn VS Code**: Phát hiện và chặn kết nối từ VS Code (kể cả GitLab Workflow extension)
- **Chặn JetBrains**: IntelliJ, PyCharm, WebStorm, PhpStorm, GoLand, v.v.
- **Chặn Eclipse, Sublime, Atom, GitKraken, SourceTree, TortoiseGit**
- **Chặn git CLI**: Có thể chặn cả git command line

### 🛡️ Bảo mật thiết bị
- **Whitelist IP**: Chỉ cho phép IP được phê duyệt kết nối
- **Whitelist thiết bị**: Phê duyệt từng thiết bị cụ thể
- **Phát hiện VS Code**: Nhận diện chính xác kết nối VS Code
- **Giới hạn thời gian**: Chỉ cho phép truy cập trong khung giờ nhất định

### 👑 Quyền admin
- **Cấp quyền tạm thời**: Admin cấp quyền clone/download cho user cụ thể
- **Cấp quyền vĩnh viễn**: Cho phép user đặc biệt truy cập không giới hạn
- **3 mức thực thi**:
  - *Audit Only*: Ghi log nhưng không chặn
  - *Soft Block*: Chặn nhưng admin có thể override
  - *Hard Block*: Chặn tuyệt đối, không ngoại lệ

### 📊 Audit Log
- Ghi log toàn bộ hoạt động: clone, download, fork, share
- Thống kê blocked IPs, events theo thời gian
- Phát hiện hoạt động đáng ngờ
- Export log để phân tích

## Kiến trúc

```
gitlab_security_addon/           # Thư mục addon (không đụng đến core)
├── app/
│   ├── controllers/admin/       # Admin controllers
│   ├── views/admin/security/    # Admin giao diện
│   ├── helpers/                 # View helpers
│   └── services/security/       # Business logic
├── lib/
│   ├── gitlab_security/         # Core module
│   │   ├── overrides/           # Ghi đè GitLab core (prepend pattern)
│   │   ├── middleware/          # Rack middleware
│   │   ├── models/              # Database models
│   │   └── api/                 # REST API endpoints
│   └── tasks/                   # Rake tasks
├── config/
│   ├── routes.rb                # Route definitions
│   └── initializers/            # Initializer mẫu
├── db/migrate/                  # Database migrations
└── README.md
```

## Cài đặt

### Yêu cầu
- GitLab CE/EE (phiên bản tương thích với Rails 7+)
- Ruby 3.1+
- PostgreSQL

### Các bước cài đặt

#### 1. Copy addon vào thư mục GitLab
```bash
cp -r gitlab_security_addon/ /path/to/gitlab/
```

#### 2. Copy initializer vào GitLab core
```bash
cp gitlab_security_addon/config/initializers/gitlab_security_addon.rb \
   /path/to/gitlab/config/initializers/
```

**LƯU Ý**: Đây là file DUY NHẤT cần copy vào core GitLab. Khi update GitLab từ upstream, chỉ cần giữ lại file này.

#### 3. Chạy migration
```bash
cd /path/to/gitlab
bundle exec rake db:migrate
```

#### 4. Cài đặt addon
```bash
bundle exec rake gitlab_security:install
```

#### 5. Khởi động lại GitLab
```bash
# Với GitLab Omnibus
sudo gitlab-ctl restart

# Với GitLab source
bundle exec rails server
```

## Sử dụng

### Admin Panel
Truy cập: `https://your-gitlab.com/admin/security_policies`

### Tạo Security Policy mới
1. Vào Admin → Security Policies → New Policy
2. Chọn loại policy: Global / Project / Group
3. Cấu hình các quyền cần chặn
4. Chọn mức thực thi (Audit/Soft/Hard)

### Cấp quyền cho user
1. Vào Admin → Security Policies → chọn policy
2. Tạo Access Grant cho user với loại quyền tương ứng
3. Có thể đặt thời hạn hoặc vĩnh viễn

### Quản lý Device Whitelist
1. Vào Admin → Device Whitelists
2. Thêm IP hoặc device được phép
3. Có thể bulk import danh sách IP

## API

### Security Policies
```bash
# List policies
GET /api/v4/security_policies

# Create policy
POST /api/v4/security_policies
{
  "name": "Block External Access",
  "policy_type": "project",
  "project_id": 123,
  "block_clone": true,
  "block_download": true,
  "enforcement_level": 2
}
```

### Access Grants
```bash
# Grant clone access to user
POST /api/v4/security_access_grants
{
  "user_id": 456,
  "project_id": 123,
  "grant_type": "clone",
  "permanent": true,
  "reason": "Approved by CTO"
}
```

### Device Whitelist
```bash
# Add device to whitelist
POST /api/v4/device_whitelists
{
  "ip_address": "192.168.1.100",
  "device_type": "vscode",
  "user_id": 456
}
```

## Bảo trì

```bash
# Kiểm tra trạng thái
bundle exec rake gitlab_security:status

# Dọn dẹp log cũ (>90 ngày)
bundle exec rake gitlab_security:cleanup_logs

# Thu hồi grant hết hạn
bundle exec rake gitlab_security:revoke_expired_grants

# Bảo trì định kỳ (chạy qua cron)
bundle exec rake gitlab_security:maintenance
```

## Nâng cấp GitLab (upstream update)

Khi GitLab có phiên bản mới:

1. Pull/merge code mới từ upstream
2. **Giữ lại file** `config/initializers/gitlab_security_addon.rb`
3. Kiểm tra xung đột (nếu có) trong thư mục `gitlab_security_addon/`
4. Chạy migration mới: `bundle exec rake db:migrate`
5. Khởi động lại GitLab

Addon được thiết kế để không đụng vào code lõi, nên việc nâng cấp thường sẽ không gặp vấn đề.

## Cấu trúc thư mục không đụng vào lõi

```
gitlab/                              # GitLab core (giữ nguyên)
├── app/                             # ← KHÔNG sửa
├── config/
│   └── initializers/
│       └── gitlab_security_addon.rb # ← File DUY NHẤT thêm vào core
├── lib/                             # ← KHÔNG sửa
└── gitlab_security_addon/           # ← TOÀN BỘ addon ở đây
    └── ... (tất cả code addon)
```

## License

MIT License - Xem file LICENSE

---

**Phát triển bởi**: anthuanphu
**Phiên bản**: 1.0.0
**Tương thích**: GitLab CE/EE
