    var apiTarget = window.location.origin;
    $(function () {
      window.swaggerUi = new SwaggerUi({
      url: apiTarget + "/api/api-docs/global",
      dom_id: "swagger-ui-container",
      validatorUrl: null,
      supportedSubmitMethods: ['get', 'post', 'put', 'delete'],
      onComplete: function(swaggerApi, swaggerUi){

        // We are taking the base path of the system API here. This will break if you should ever rename it lol.
        if(swaggerApi.System && !apiTarget.lastIndexOf(swaggerApi.System.basePath, 0) === 0)   {
          alert("IMPORTANT: Please use the configured REST transport address (" + swaggerApi.System.basePath + ") if you want working examples. " +
                  "This connection to " + apiTarget + " will cause problems with Access-Control-Allow-Origin.");
        }

        if(console) {
          console.log("Loaded SwaggerUI")
        }
        $('pre code').each(function(i, e) {hljs.highlightBlock(e)});

        //if ("${showWarning}") {
          $('.warning-box').css('visibility', '');
        //}
      },
      onFailure: function(data) {
        if(console) {
          console.log("Unable to Load SwaggerUI");
          console.log(data);
        }
      },
      docExpansion: "none"
    });

    window.swaggerUi.load();

    var updateApiAuth = function() {
        var user = $('#input_apiUser')[0].value;
        var pass = $('#input_apiPassword')[0].value;
        if(user && user.trim() != "" && pass && pass.trim() != "") {
            swaggerUi.api.clientAuthorizations.add("basic", new SwaggerClient.PasswordAuthorization(user, pass));
        }
    };
    $('#input_apiUser').change(updateApiAuth);
    $('#input_apiPassword').change(updateApiAuth);

    // Add CSRF header
    swaggerUi.api.clientAuthorizations.add("csrf", new SwaggerClient.ApiKeyAuthorization("X-Requested-By", "Graylog API Browser", "header"));

  });
