namespace AppAuth.Authentication;

uses
  AppAuth,
  RemObjects.Elements.Linq,
  Sugar,
  Foundation, UIKit;
  
type

  AuthenticationViewController = public abstract class(UIViewController,IOIDAuthStateChangeDelegate,IOIDAuthStateErrorDelegate)
  private
  
    method saveState;
    begin
      var archivedAuthState: NSData := NSKeyedArchiver.archivedDataWithRootObject(_authState);
      NSUserDefaults.standardUserDefaults().setObject(archivedAuthState) forKey(appAuthExampleAuthStateKey);
      NSUserDefaults.standardUserDefaults().synchronize();
    end;
  
    // IOIDAuthStateChangeDelegate
    method didChangeState(state: not nullable OIDAuthState);
    begin
      self.stateChanged();
    end;
    
    method authState(state: OIDAuthState) didEncounterAuthorizationError(error: NSError);
    begin
      self.logMessage('Received authorization error: {0}', error);
    end;
    
    method authState(state: OIDAuthState) didEncounterTransientError(error: NSError);
    begin
      self.logMessage('Received transient error: {0}', error);
    end;
    
    method cancel;
    begin
    end;
    
    // verifies that the custom URI scheme has been updated in the Info.plist
    method verifyCustomScheme;
    begin
      
      var urlTypes:NSArray := NSBundle.mainBundle.objectForInfoDictionaryKey('CFBundleURLTypes');
      
      if(not (urlTypes.Any))then
      begin
        raise new NSException withName('') reason('No urlTypes.') userInfo(nil);
      end;
      
      var urlSchemes: NSArray := NSDictionary(urlTypes.objectAtIndex(0)).objectForKey('CFBundleURLSchemes');
      
      if(not (urlSchemes.Any))then
      begin
        raise new NSException withName('') reason('No custom URI scheme has been configured for the project.') userInfo(nil);
      end;
      
      var urlScheme: NSString := urlSchemes.objectAtIndex(0);
      
      if(String. isNullOrEmpty(urlScheme))then
      begin
        raise new NSException withName('') reason('No scheme.') userInfo(nil);
      end;
      
    end;
    
    method logMessage(format: NSString;params param1: array of dynamic);
    begin
      
      //var log := String.Format(format,param1);
      //NSLog('%@', log);
      //NSLog(format,param1);
      {
      // outputs to output log
      var dateFormatter: NSDateFormatter := new NSDateFormatter;
      dateFormatter.dateFormat := 'hh:mm:ss';
      var dateString: NSString := dateFormatter.stringFromDate(NSDate.date());
      logTextView.text := NSString.stringWithFormat('%@%@%@: %@', logTextView.text, iif(logTextView.text.length() > 0,'\n',''),dateString,log);
      }
    end;
    
  protected
  
    method issuerURL:NSURL;abstract;
    method clientID:not nullable String;abstract;
    method appAuthExampleAuthStateKey:not nullable String;abstract;
    method redirectURL:NSURL;abstract;
  
    property _authState:OIDAuthState;
    
    method stateChanged;virtual;
    begin
      self.saveState();
    end;
  
    method loadState;
    begin
      var archivedAuthState: NSData := NSUserDefaults.standardUserDefaults().objectForKey(appAuthExampleAuthStateKey);
      var someState := OIDAuthState(NSKeyedUnarchiver.unarchiveObjectWithData(archivedAuthState));
      self.setAuthState(someState);
    end;
    
    method setAuthState(authState: OIDAuthState);
    begin
      _authState := authState;
      _authState:stateChangeDelegate := self;
      self.stateChanged();
    end;
        
    method doCodeExchange;
    begin
      var tokenExchangeRequest: OIDTokenRequest := _authState.lastAuthorizationResponse.tokenExchangeRequest();
      self.logMessage('Performing authorization code exchange with request [%@]', tokenExchangeRequest);
      
      OIDAuthorizationService.performTokenRequest(tokenExchangeRequest) callback(method (tokenResponse: AppAuth.OIDTokenResponse; error: NSError) begin
        
        if(not assigned(tokenResponse))then
        begin
          self.logMessage('Token exchange error: %@', error.localizedDescription());
        end
        else
        begin
          self.logMessage('Received token response with accessToken: %@', tokenResponse.accessToken);
        end;
        _authState.updateWithTokenResponse(tokenResponse) error(error);
      end);
      
    end;
    
    method getUserInfo;
    begin
      var userinfoEndpoint: NSURL := _authState.lastAuthorizationResponse.request.configuration.discoveryDocument.userinfoEndpoint;
      
      if not assigned(userinfoEndpoint) then
      begin
        self.logMessage('Userinfo endpoint not declared in discovery document');
        exit;
      end;
      
      var currentAccessToken: NSString := _authState.lastTokenResponse.accessToken;
      
      self.logMessage('Performing userinfo request');
      
      _authState.withFreshTokensPerformAction((accessToken, idToken, error) -> begin
        if assigned(error) then
        begin
          self.logMessage('Error fetching fresh tokens: %@', error.localizedDescription());
          exit;
        end;
        if currentAccessToken ≠ accessToken then
        begin
          self.logMessage('Access token was refreshed automatically (%@ to %@)', currentAccessToken, accessToken);
        end
        else
        begin
          self.logMessage('Access token was fresh and not updated [%@]', accessToken);
        end;
        
        var request: NSMutableURLRequest := NSMutableURLRequest.requestWithURL(userinfoEndpoint);
        var authorizationHeaderValue: NSString := NSString.stringWithFormat('Bearer %@', accessToken);
        request.addValue(authorizationHeaderValue) forHTTPHeaderField('Authorization');
        var configuration: NSURLSessionConfiguration := NSURLSessionConfiguration.defaultSessionConfiguration();
        var session: NSURLSession := NSURLSession.sessionWithConfiguration(configuration) &delegate(nil) delegateQueue(nil);
        
        var postDataTask: NSURLSessionDataTask := session.dataTaskWithRequest(request) completionHandler((data, response, taskError) ->
        
        dispatch_async(dispatch_get_main_queue(), () -> begin
          if not response.isKindOfClass(NSHTTPURLResponse.class()) then
          begin
            self.logMessage('Non-HTTP response %@', taskError);
            exit;
          end;
          var httpResponse: NSHTTPURLResponse := NSHTTPURLResponse(response);
          var jsonError: NSError;
          var jsonDictionaryOrArray: id := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonError);
          if httpResponse.statusCode ≠ 200 then
          begin
            var responseText: NSString := new NSString WithData(data) encoding(NSStringEncoding.NSUTF8StringEncoding);
            if httpResponse.statusCode = 401 then
            begin
              var oauthError: NSError := OIDErrorUtilities.resourceServerAuthorizationErrorWithCode(0) errorResponse(jsonDictionaryOrArray) underlyingError(taskError);
              _authState.updateWithAuthorizationError(oauthError);
              self.logMessage('Authorization Error (%@). Response: %@', oauthError, responseText);
            end
            else begin
              self.logMessage('HTTP: %d. Response: %@', Integer(httpResponse.statusCode), responseText);
            end;
            exit;
          end;
          self.logMessage('Success: %@', jsonDictionaryOrArray);
        end));
        
        postDataTask.resume();
      end);
      
    end;
    
    method doAuthNoCodeExchange;
    begin
      var issuer: NSURL := issuerURL;
      var redirectURI: NSURL := redirectURL;
      
      self.logMessage('Fetching configuration for issuer: %@', issuer);
      
      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration:nullable OIDServiceConfiguration; error: nullable NSError) begin
        
        if not assigned(configuration) then
        begin
          self.logMessage('Error retrieving discovery document: %@', error.localizedDescription());
          exit;
        end;
        self.logMessage('Got configuration: %@', configuration);
          
        var request: OIDAuthorizationRequest := new OIDAuthorizationRequest withConfiguration(configuration) clientId(clientID) scopes([OIDScopeOpenID, OIDScopeProfile]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);
        var appDelegate: AuthenticationAppDelegate := (UIApplication.sharedApplication.&delegate) as AuthenticationAppDelegate;
        
        self.logMessage('Initiating authorization request %@', request);
          
        appDelegate.currentAuthorizationFlow := OIDAuthorizationService.presentAuthorizationRequest(request) presentingViewController(self) callback(method (authorizationResponse: AppAuth.OIDAuthorizationResponse; presentError: NSError) begin
            
          if assigned(authorizationResponse) then
          begin
            var authState: OIDAuthState := new OIDAuthState withAuthorizationResponse(authorizationResponse);
            self.setAuthState(authState);
            self.logMessage('Authorization response with code: %@', authorizationResponse.authorizationCode);
          end
          else begin
            self.logMessage('Authorization error: %@', error.localizedDescription());
          end;
            
        end);
        
      end);
      
    end;
    
    method doAuthWithAutoCodeExchange;
    begin
      var issuer:NSURL := issuerURL;
      var redirectURI:NSURL := redirectURL;
      
      self.logMessage('Fetching configuration for issuer: %@', issuer);
      
      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration: OIDServiceConfiguration; error: NSError) begin
        if(not assigned(configuration))then
        begin
          self.logMessage('Error retrieving discovery document: %@', error.localizedDescription());
          self.setAuthState(nil);
          exit;
        end;
          
        self.logMessage('Got configuration: %@', configuration);
          
        var request := new OIDAuthorizationRequest withConfiguration(configuration) clientId(clientID) scopes([OIDScopeOpenID, OIDScopeProfile]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);
            
        var appDelegate: AuthenticationAppDelegate := (UIApplication.sharedApplication.&delegate) as AuthenticationAppDelegate;
        self.logMessage('Initiating authorization request with scope: %@', request.scope);
          
        appDelegate.currentAuthorizationFlow := OIDAuthState.authStateByPresentingAuthorizationRequest(request)  presentingViewController(self) callback(method (authState: AppAuth.OIDAuthState; authRequestError: NSError) begin
            
          if(assigned(authState))then
          begin
            self.setAuthState(authState);
            self.logMessage('Got authorization tokens. Access token: %@', authState.lastTokenResponse.accessToken);
          end
          else
          begin
            self.logMessage('Authorization error: %@', authRequestError.localizedDescription());
            self.setAuthState(nil);
          end;
        end);
          
          
      end);
      
    end;
    
    public
      method viewDidLoad; override;
      begin
        inherited viewDidLoad;
      
        self.verifyCustomScheme;
        self.loadState();
      
      end;    
    
    
    
    
  end;

end.
