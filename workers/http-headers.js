export default {
  async fetch(request, env, ctx) {

    const response = await fetch(request);

    const newResponse = new Response(response.body, response);


    // Defines which sources the browser is allowed to load resources from
    // Limits the damage if an attacker manages to inject malicious scripts (XSS)
    newResponse.headers.set(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    );

    // Prevents the site from being embedded inside an iframe on another domain
    // Stops clickjacking — where an attacker tricks users into clicking hidden buttons on your site
    newResponse.headers.set(
      "X-Frame-Options",
      "DENY"
    );

    // Stops the browser from guessing the file type when the server already declared it
    // Prevents MIME sniffing attacks where a malicious file pretends to be something harmless
    newResponse.headers.set(
      "X-Content-Type-Options",
      "nosniff"
    );

    // Forces the browser to always use HTTPS for this site for the next year
    // Prevents downgrade attacks where an attacker forces the connection back to plain HTTP
    newResponse.headers.set(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload"
    );


    return newResponse;
    
  },
};