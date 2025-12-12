<?php

namespace Hokibgs\AuthCenter;

use Exception;

class AuthCenter
{
    protected string $apiUrl;
    protected string $clientId;
    protected string $clientSecret;

    protected string $cipher = 'AES-256-CBC';
    protected string $key;
    protected string $iv;

    protected ?string $token = null;
    protected array $additionalHeaders = [];

    public function __construct(string $apiUrl, string $clientId, string $clientSecret)
    {
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;

        $this->key = md5($clientSecret);
        $this->iv = $this->generateIV();
    }

    public function setToken(?string $token): self
    {
        $this->token = $token;
        return $this;
    }

    public function setHeaders(array $headers): self
    {
        $this->additionalHeaders = $headers;
        return $this;
    }

    protected function generateIV(): string
    {
        $ivlen = openssl_cipher_iv_length($this->cipher);
        return substr(md5(uniqid()), 0, $ivlen);
    }

    protected function encrypt($data): string
    {
        if (is_array($data) || is_object($data)) {
            $data = json_encode($data);
        }

        $encrypted = openssl_encrypt($data, $this->cipher, $this->key, false, $this->iv);
        return base64_encode($encrypted);
    }

    protected function encryptLoginPassword(string $password): string
    {
        return $this->encrypt($password);
    }

    protected function makeSignature($payload): string
    {
        return $this->encrypt($payload);
    }

    protected function buildHeaders(array $payload): array
    {
        $headers = [
            "Accept: application/json",
            "X-Client-Id: {$this->clientId}",
            "X-Client-Iv: " . base64_encode($this->iv),
            "Signature: " . $this->makeSignature($payload),
            "Authorization: " . ($this->token ?? ''),
            "X-Forwarded-For: " . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''),
            "User-Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? ''),
            "x-auth-ip: " . ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''),
        ];

        foreach ($this->additionalHeaders as $key => $value) {
            $headers[] = "$key: $value";
        }

        return $headers;
    }

    protected function request(string $method, string $url, array $data = [], array $signaturePayload = null)
    {
        $signaturePayload = $signaturePayload ?? $data;

        $fullUrl = $this->apiUrl . $url;
        $ch = curl_init();
        $headers = $this->buildHeaders($signaturePayload);

        switch (strtoupper($method)) {
            case 'GET':
            case 'DELETE':
                if (!empty($data)) {
                    $fullUrl .= '?' . http_build_query($data);
                }
                break;

            case 'POST':
            case 'PUT':
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                $headers[] = "Content-Type: application/json";
                break;
        }

        curl_setopt_array($ch, [
            CURLOPT_URL            => $fullUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 30,
        ]);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            throw new Exception("cURL error: " . curl_error($ch));
        }

        return json_decode($response);
    }

    protected function encryptPasswordFields(array $data): array
    {
        foreach (['password', 'password_confirmation', 'old_password'] as $field) {
            if (isset($data[$field])) {
                $data[$field] = $this->encrypt($data[$field]);
            }
        }
        return $data;
    }

    public function get(string $url, array $query = [])
    {
        return $this->request('GET', $url, $query, $query);
    }

    public function delete(string $url, array $query = [])
    {
        return $this->request('DELETE', $url, $query, $query);
    }

    public function post(string $url, array $body = [])
    {
        $body = $this->encryptPasswordFields($body);
        return $this->request('POST', $url, $body, $body);
    }

    public function put(string $url, array $body = [])
    {
        $body = $this->encryptPasswordFields($body);
        return $this->request('PUT', $url, $body, $body);
    }

    public function login(string $email, string $password)
    {
        $payload = [
            'email' => $email,
            'password' => $this->encryptLoginPassword($password),
        ];

        return $this->request('POST', '/auth/login', $payload, $payload);
    }

    public function getProfile(string $email)
    {
        return $this->get('/account/profile', ['email' => $email]);
    }
}
