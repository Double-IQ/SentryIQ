<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,follow">
<title>Credits &amp; Acknowledgements — SentryIQ</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
<style>
.credits-page{max-width:820px;margin:36px auto;padding:28px}
.credits-page h1{margin-top:0}
.credits-intro{color:var(--text-muted,#667085);line-height:1.65}
.credits-list{display:grid;gap:14px;margin:26px 0}
.credit-item{padding:16px 18px;border:1px solid var(--border-color,#d9dee7);border-radius:12px;background:var(--card-bg,rgba(127,127,127,.035))}
.credit-item h2{font-size:1.05rem;margin:0 0 6px}
.credit-item p{margin:0;line-height:1.55}
.credit-item a{overflow-wrap:anywhere}
.credits-note{font-size:.9rem;line-height:1.6;color:var(--text-muted,#667085)}
.credits-back{display:inline-block;margin-top:10px}
</style>
</head>
<body>
<main class="box credits-page">
    <h1>Credits &amp; Acknowledgements</h1>
    <p class="credits-intro">SentryIQ is made possible by the tools, standards, services and communities below. With sincere thanks to the people who build and maintain them.</p>

    <section class="credits-list" aria-label="Project credits">
        <article class="credit-item">
            <h2><a href="https://www.backblaze.com/cloud-storage" target="_blank" rel="noopener noreferrer">Backblaze</a></h2>
            <p>Backblaze B2 Cloud Storage — the planned object-storage home for encrypted Gallery photos.</p>
        </article>
        <article class="credit-item">
            <h2><a href="https://openai.com/" target="_blank" rel="noopener noreferrer">OpenAI</a></h2>
            <p>ChatGPT assistance with SentryIQ planning, architecture, implementation and technical review.</p>
        </article>
        <article class="credit-item">
            <h2><a href="https://git-scm.com/" target="_blank" rel="noopener noreferrer">Git</a></h2>
            <p>Distributed version control that helps track changes and manage the project's development history.</p>
        </article>
        <article class="credit-item">
            <h2><a href="https://github.com/" target="_blank" rel="noopener noreferrer">GitHub</a></h2>
            <p>Repository hosting, issue tracking, collaboration and automated checks for the SentryIQ project.</p>
        </article>
        <article class="credit-item">
            <h2><a href="https://www.linux.org/" target="_blank" rel="noopener noreferrer">Linux</a></h2>
            <p>The Linux ecosystem and its contributors, whose open-source work powers a huge part of the internet and modern hosting.</p>
        </article>
        <article class="credit-item">
            <h2><a href="https://www.php.net/" target="_blank" rel="noopener noreferrer">PHP</a></h2>
            <p>The server-side language and runtime used to build SentryIQ.</p>
        </article>
        <article class="credit-item">
            <h2><a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API" target="_blank" rel="noopener noreferrer">Web Crypto API</a></h2>
            <p>Browser-native cryptographic primitives used by the client-side Gallery encryption design.</p>
        </article>
        <article class="credit-item">
            <h2><a href="https://www.w3.org/TR/webauthn-3/" target="_blank" rel="noopener noreferrer">W3C WebAuthn</a> &amp; <a href="https://fidoalliance.org/passkeys/" target="_blank" rel="noopener noreferrer">FIDO Alliance</a></h2>
            <p>Open standards and ecosystem work behind secure, phishing-resistant passkey authentication.</p>
        </article>
    </section>

    <p class="credits-note">SentryIQ is an independent project. Names and trademarks belong to their respective owners. Listing an organisation or project here is an acknowledgement of its tools or contribution; it does not imply sponsorship, endorsement or an official partnership.</p>
    <a class="btn btn-primary credits-back" href="index.php">← Back to SentryIQ</a>
</main>
</body>
</html>
