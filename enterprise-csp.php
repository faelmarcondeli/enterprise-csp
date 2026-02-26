<?php
/*
Plugin Name: Enterprise CSP for WordPress
Description: Strict CSP with nonce, strict-dynamic, and automatic inline style hashing.
Version: 1.0
*/

if (!defined('ABSPATH')) exit;

class Enterprise_CSP {

    private $nonce;
    private $style_hashes = [];

    public function __construct() {
        add_action('init', [$this, 'init_nonce'], 1);
        add_action('send_headers', [$this, 'send_csp_header'], 20);
        add_filter('script_loader_tag', [$this, 'add_nonce_to_scripts'], 10, 3);
        add_action('template_redirect', [$this, 'start_buffer']);
    }

    public function init_nonce() {
        if (!is_admin()) {
            $this->nonce = base64_encode(random_bytes(16));
        }
    }

    public function get_nonce() {
        return $this->nonce;
    }

    public function add_nonce_to_scripts($tag, $handle, $src) {
        if ($this->nonce) {
            return str_replace('<script ', '<script nonce="' . esc_attr($this->nonce) . '" ', $tag);
        }
        return $tag;
    }

    public function start_buffer() {
        if (!is_admin()) {
            ob_start([$this, 'capture_inline_styles']);
        }
    }

    public function capture_inline_styles($html) {
        if (preg_match_all('#<style[^>]*>(.*?)</style>#is', $html, $matches)) {
            foreach ($matches[1] as $style_content) {
                $hash = base64_encode(hash('sha256', trim($style_content), true));
                $this->style_hashes[] = "'sha256-{$hash}'";
            }
        }
        return $html;
    }

    public function send_csp_header() {

        if (is_admin()) return;

        $style_hash_string = implode(' ', array_unique($this->style_hashes));

        $csp = "
        default-src 'none';
        script-src 'nonce-{$this->nonce}' 'strict-dynamic';
        style-src 'self' {$style_hash_string} https://fonts.googleapis.com https://*.quic.cloud;
        font-src 'self' https://fonts.gstatic.com data:;
        img-src 'self' data: blob: https:;
        connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://*.onesignal.com https://*.pagar.me https://*.bancointer.com.br https://*.melhorenvio.com.br https://*.quic.cloud https://*.litespeedcdn.com;
        frame-src https://*.pagar.me https://*.bancointer.com.br;
        worker-src 'self' blob:;
        object-src 'none';
        base-uri 'self';
        frame-ancestors 'self';
        form-action 'self' https://*.pagar.me https://*.bancointer.com.br;
        upgrade-insecure-requests;
        ";

        header("Content-Security-Policy: " . preg_replace('/\s+/', ' ', trim($csp)));
    }
}

new Enterprise_CSP();
