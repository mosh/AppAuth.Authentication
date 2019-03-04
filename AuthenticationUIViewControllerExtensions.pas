namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation, UIKit;

type

  AuthenticationUIViewControllerExtensions = public extension class(UIViewController)

  private

    method doAuthWithAutoCodeExchange;
    begin
      NSLog('%@','doAuthWithAutoCodeExchange');
      var issuer:NSURL := AppDelegate.AuthenticationService.issuerURL;
      var redirectURI:NSURL := AppDelegate.AuthenticationService.redirectURL;

      AppDelegate.InAuthorizationFlow := true;

      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration: OIDServiceConfiguration; error: NSError)
      begin

        if(assigned(error))then
        begin
          NSLog('%@',$'discoverServiceConfigurationForIssuer completion with error {error.localizedDescription}');
          AppDelegate.AuthenticationService.AuthState := nil;
          AppDelegate.InAuthorizationFlow := false;
          exit;
        end
        else
        begin
          NSLog('%@',$'discoverServiceConfigurationForIssuer completion success');
        end;

        var request := new OIDAuthorizationRequest withConfiguration(configuration) clientId(AppDelegate.AuthenticationService.clientID) scopes([OIDScopeOpenID, OIDScopeProfile,OIDScopeEmail]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);

        NSLog('Initiating authorization request with scope: %@', request.scope);

        appDelegate.currentAuthorizationFlow := OIDAuthState.authStateByPresentingAuthorizationRequest(request)  presentingViewController(self) callback(method (authState: AppAuth.OIDAuthState; authRequestError: NSError)
        begin

          AppDelegate.InAuthorizationFlow := false;

          if(assigned(authState))then
          begin
            NSLog('%@',$'authStateByPresentingAuthorizationRequest callback with access token {authState.lastTokenResponse.accessToken}');
            AppDelegate.AuthenticationService.AuthState := authState;
          end
          else
          begin
            NSLog('%@',$'authStateByPresentingAuthorizationRequest callback with error {authRequestError:localizedDescription}');
            AppDelegate.AuthenticationService.AuthState := nil;
          end;
        end);

      end);

    end;

  public

    property AppDelegate:AuthenticationAppDelegate read
      begin
        exit (UIApplication.sharedApplication.&delegate) as AuthenticationAppDelegate;
      end;

    method performAuthentication;
    begin
      self.doAuthWithAutoCodeExchange;
    end;

  end;

end.