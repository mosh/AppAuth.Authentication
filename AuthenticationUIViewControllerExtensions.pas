namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation, UIKit;

type

  AuthenticationUIViewControllerExtensions = public extension class(UIViewController)
  public
  
    method doCodeExchange;
    begin
      var tokenExchangeRequest: OIDTokenRequest := AuthenticationService.Instance.AuthState.lastAuthorizationResponse.tokenExchangeRequest();
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
        AuthenticationService.Instance.AuthState.updateWithTokenResponse(tokenResponse) error(error);
      end);
      
    end;
  
  
    method doAuthNoCodeExchange;
    begin
      var issuer: NSURL := AuthenticationService.Instance.issuerURL;
      var redirectURI: NSURL := AuthenticationService.Instance.redirectURL;
      
      NSLog('Fetching configuration for issuer: %@', issuer);
      
      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration:nullable OIDServiceConfiguration; error: nullable NSError)
      begin
        
        if not assigned(configuration) then
        begin
          NSLog('Error retrieving discovery document: %@', error.localizedDescription());
          exit;
        end;
        
        NSLog('Got configuration: %@', configuration);
          
        var request: OIDAuthorizationRequest := new OIDAuthorizationRequest withConfiguration(configuration) clientId(AuthenticationService.Instance.clientID) scopes([OIDScopeOpenID, OIDScopeProfile]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);
        var appDelegate: AuthenticationAppDelegate := (UIApplication.sharedApplication.&delegate) as AuthenticationAppDelegate;
        
        NSLog('Initiating authorization request %@', request);
          
        appDelegate.currentAuthorizationFlow := OIDAuthorizationService.presentAuthorizationRequest(request) presentingViewController(self) callback(method (authorizationResponse: AppAuth.OIDAuthorizationResponse; presentError: NSError)
        begin
            
          if assigned(authorizationResponse) then
          begin
            AuthenticationService.Instance.AuthState := new OIDAuthState withAuthorizationResponse(authorizationResponse);
            NSLog('Authorization response with code: %@', authorizationResponse.authorizationCode);
          end
          else
          begin
            NSLog('Authorization error: %@', error.localizedDescription());
          end;
            
        end);
        
      end);
      
    end;
    
    method doAuthWithAutoCodeExchange;
    begin
      var issuer:NSURL := AuthenticationService.Instance.issuerURL;
      var redirectURI:NSURL := AuthenticationService.instance.redirectURL;
      
      NSLog('Fetching configuration for issuer: %@', issuer);
      
      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration: OIDServiceConfiguration; error: NSError)
      begin
        
        if(not assigned(configuration))then
        begin
          NSLog('Error retrieving discovery document: %@', error.localizedDescription());
          AuthenticationService.Instance.AuthState := nil;
          exit;
        end;
          
        NSLog('Got configuration: %@', configuration);
          
        var request := new OIDAuthorizationRequest withConfiguration(configuration) clientId(AuthenticationService.Instance.clientID) scopes([OIDScopeOpenID, OIDScopeProfile]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);
            
        var appDelegate: AuthenticationAppDelegate := (UIApplication.sharedApplication.&delegate) as AuthenticationAppDelegate;
        NSLog('Initiating authorization request with scope: %@', request.scope);
          
        appDelegate.currentAuthorizationFlow := OIDAuthState.authStateByPresentingAuthorizationRequest(request)  presentingViewController(self) callback(method (authState: AppAuth.OIDAuthState; authRequestError: NSError)
        begin
            
          if(assigned(authState))then
          begin
            AuthenticationService.Instance.AuthState := authState;
            NSLog('Got authorization tokens. Access token: %@', authState.lastTokenResponse.accessToken);
          end
          else
          begin
            NSLog('Authorization error: %@', authRequestError.localizedDescription());
            AuthenticationService.Instance.AuthState := nil;
          end;
        end);
          
          
      end);
      
    end;
    
  end;

end.
