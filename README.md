# Auth Center PHP

Library PHP untuk login ke SMB Auth Center

## Instalasi

```bash
composer require hokibgs/auth-center
```
## Cara Penggunaan

#### 🔧 Inisialisasi Client

```javascript
use Hokibgs\AuthCenter\AuthCenter;

$auth = new AuthCenter(
    apiUrl: 'https://auth-center.example.com',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret'
);
```
#### 🔐 Login

```javascript
$response = $auth->login('email@example.com', 'password123');
```

#### 👤 Ambil Profile

```javascript
$auth->setToken('auth-token');
$profile = $auth->getProfile('email@example.com');
```

#### 📡 Request GET

```javascript
$auth->setToken('auth-token');
$response = $auth->get('/users');
```

#### 📝 Request POST

```javascript
$response = $auth->post('/auth/register', [
    'email' => 'user@example.com',
    'password' => 'secret',
    'password_confirmation' => 'secret',
]);
```

#### 🔄 Request PUT

```javascript
$auth->setToken('auth-token');
$response = $auth->put('/auth/change-password', [
    'old_password' => 'oldpass',
    'password' => 'newpass',
]);
```

#### ❌ Request DELETE

```javascript
$auth->setToken('auth-token');
$response = $auth->delete('/account/remove', ['email' => 'user@example.com']);
```

#### 📤 Menambahkan Custom Headers

```javascript
$auth->setHeaders([
    'X-My-App' => 'CustomHeaderValue'
]);
```
