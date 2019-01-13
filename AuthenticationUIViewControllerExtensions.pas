namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation, UIKit;

type

  AuthenticationUIViewControllerExtensions = public extension class(UIViewController)

  private

    property AppDelegate:AuthenticationAppDelegate read
      begin
        exit (UIApplication.sharedApplication.&delegate) as AuthenticationAppDelegate;
      end;



  public

    method doCodeExchange;
    begin
      var tokenExchangeRequest: OIDTokenRequest := AppDelegate.AuthenticationService.AuthState.lastAuthorizationResponse.tokenExchangeRequest();
      NSLog('Performing authorization code exchange with request [%@]', tokenExchangeRequest);

      OIDAuthorizationService.performTokenRequest(tokenExchangeRequest) callback(method (tokenResponse: OIDTokenResponse; error: NSError)
      begin

        if(not assigned(tokenResponse))then
        begin
          raise new NSException withName('') reason(error.localizedDescription()) userInfo(nil);
        end
        else
        begin
          NSLog('Received token response with accessToken: %@', tokenResponse.accessToken);
        end;
        AppDelegate.AuthenticationService.AuthState.updateWithTokenResponse(tokenResponse) error(error);
      end);

    end;


    method doAuthNoCodeExchange;
    begin
      var issuer: NSURL := AppDelegate.AuthenticationService.issuerURL;
      var redirectURI: NSURL := AppDelegate.AuthenticationService.redirectURL;

      NSLog('Fetching configuration for issuer: %@', issuer);

      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration:nullable OIDServiceConfiguration; error: nullable NSError)
      begin

        if not assigned(configuration) then
        begin
          NSLog('Error retrieving discovery document: %@', error.localizedDescription());
          exit;
        end;

        NSLog('Got configuration: %@', configuration);

        var request: OIDAuthorizationRequest := new OIDAuthorizationRequest withConfiguration(configuration) clientId(AppDelegate.AuthenticationService.clientID) scopes([OIDScopeOpenID, OIDScopeProfile, OIDScopeEmail]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);

        NSLog('Initiating authorization request %@', request);

        appDelegate.currentAuthorizationFlow := OIDAuthorizationService.presentAuthorizationRequest(request) presentingViewController(self) callback(method (authorizationResponse: AppAuth.OIDAuthorizationResponse; presentError: NSError)
        begin

          if assigned(authorizationResponse) then
          begin
            var authState := new OIDAuthState withAuthorizationResponse(authorizationResponse);
            AppDelegate.AuthenticationService.AuthState := authState;
            NSLog('Authorization response with code: %@', authorizationResponse.authorizationCode);
          end
          else
          begin
            NSLog('Authorization error: %@', error:localizedDescription());
          end;

        end);

      end);

    end;

    method doAuthWithAutoCodeExchange;
    begin
      var issuer:NSURL := AppDelegate.AuthenticationService.issuerURL;
      var redirectURI:NSURL := AppDelegate.AuthenticationService.redirectURL;

      NSLog('Fetching configuration for issuer: %@', issuer);

      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration: OIDServiceConfiguration; error: NSError)
      begin

        if(not assigned(configuration))then
        begin
          NSLog('Error retrieving discovery document: %@', error.localizedDescription());
          AppDelegate.AuthenticationService.AuthState := nil;
          exit;
        end;

        NSLog('Got configuration: %@', configuration);

        var request := new OIDAuthorizationRequest withConfiguration(configuration) clientId(AppDelegate.AuthenticationService.clientID) scopes([OIDScopeOpenID, OIDScopeProfile,OIDScopeEmail]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);

        NSLog('Initiating authorization request with scope: %@', request.scope);

        appDelegate.currentAuthorizationFlow := OIDAuthState.authStateByPresentingAuthorizationRequest(request)  presentingViewController(self) callback(method (authState: AppAuth.OIDAuthState; authRequestError: NSError)
        begin

          if(assigned(authState))then
          begin

            AppDelegate.AuthenticationService.AuthState := authState;
            NSLog('Got authorization tokens. Access token: %@', authState.lastTokenResponse.accessToken);
          end
          else
          begin
            NSLog('Authorization error: %@', authRequestError:localizedDescription());
            AppDelegate.AuthenticationService.AuthState := nil;
          end;
        end);


      end);

    end;

  end;

end.