namespace AppAuth.Authentication;

uses
  AppAuth,
  RemObjects.Elements.Linq,
  Sugar,
  Foundation,
  UIKit;
  
type

  AuthenticationViewController = public abstract class(UIViewController,IOIDAuthStateChangeDelegate,IOIDAuthStateErrorDelegate)
  
  private
  
    method get_Expired:Boolean;
    begin
      
      if(not assigned(_authState)) or ((assigned(_authState)) and (not assigned(_authState.lastTokenResponse))) then
      begin
        exit false;
      end;
      
      var expiryDate := DateTime(_authState.lastTokenResponse.accessTokenExpirationDate);
      
      var currentTime := new DateTime;
      
      if(expiryDate < currentTime)then
      begin
        exit true;
      end;
      
      exit false;
    end;
    
    method get_Authorized:Boolean;
    begin
      exit iif(assigned(_authState),_authState.isAuthorized(),false);
    end;
  
    method fillUserInfo(info:UserInfo; jsonDictionaryOrArray:id);
    begin
      info.FamilyName := jsonDictionaryOrArray['family_name'];
      info.Gender := jsonDictionaryOrArray['gender'];
      info.GivenName := jsonDictionaryOrArray['given_name'];
      info.Locale := jsonDictionaryOrArray['locale'];
      info.Name := jsonDictionaryOrArray['name'];
      info.Picture := jsonDictionaryOrArray['picture'];
    end;
    
    method processResponse(info:UserInfo;data:NSData; httpResponse: NSHTTPURLResponse;taskError:NSError);
    begin
      var jsonError: NSError;
            
      var jsonDictionaryOrArray: id := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonError);
            
      if httpResponse.statusCode ≠ 200 then
      begin
        var responseText: NSString := new NSString WithData(data) encoding(NSStringEncoding.NSUTF8StringEncoding);
              
        if httpResponse.statusCode = 401 then
        begin
          var oauthError: NSError := OIDErrorUtilities.resourceServerAuthorizationErrorWithCode(0) errorResponse(jsonDictionaryOrArray) underlyingError(taskError);
          _authState.updateWithAuthorizationError(oauthError);
          NSLog('Authorization Error (%@). Response: %@', oauthError, responseText);
        end
        else
        begin
          NSLog('HTTP: %d. Response: %@', Integer(httpResponse.statusCode), responseText);
        end;
              
        exit;
      end;
            
      fillUserInfo(info,jsonDictionaryOrArray);
            
      NSLog('Success: %@', jsonDictionaryOrArray);
      
      
    end;
    
  
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
      NSLog('Received authorization error: %@', error);
    end;
    
    method authState(state: OIDAuthState) didEncounterTransientError(error: NSError);
    begin
      NSLog('Received transient error: %@', error);
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
        _authState.updateWithTokenResponse(tokenResponse) error(error);
      end);
      
    end;
    
    method getUserInfo:UserInfo;
    begin
      var userinfoEndpoint: NSURL := _authState.lastAuthorizationResponse.request.configuration.discoveryDocument.userinfoEndpoint;
      var info := new UserInfo;
      
      if not assigned(userinfoEndpoint) then
      begin
        raise new NSException withName('') reason('Userinfo endpoint not declared in discovery document') userInfo(nil);
      end;
      
      var outerExecutionBlock: NSBlockOperation := NSBlockOperation.blockOperationWithBlock(method begin
      
        var semaphore := dispatch_semaphore_create(0);
        
        var accessToken := _authState.lastTokenResponse.accessToken;
        
        var request: NSMutableURLRequest := NSMutableURLRequest.requestWithURL(userinfoEndpoint);
        var authorizationHeaderValue: NSString := NSString.stringWithFormat('Bearer %@', accessToken);
        request.addValue(authorizationHeaderValue) forHTTPHeaderField('Authorization');
        var configuration: NSURLSessionConfiguration := NSURLSessionConfiguration.defaultSessionConfiguration();
        var session: NSURLSession := NSURLSession.sessionWithConfiguration(configuration) &delegate(nil) delegateQueue(nil);
        
        var postDataTask: NSURLSessionDataTask := session.dataTaskWithRequest(request) completionHandler((data, response, taskError) ->
        begin
              
          var responseClass := NSHTTPURLResponse.class;
          var isKindOf := response.isKindOfClass(responseClass);
              
          if (not isKindOf) then
          begin
            NSLog('Non-HTTP response %@', taskError);
            exit;
          end;
              
          processResponse(info,data,NSHTTPURLResponse(response),taskError);
          dispatch_semaphore_signal(semaphore);
            
        end);
        
        postDataTask.resume;
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);      

      end);
      
      var workerQueue := new NSOperationQueue();
      workerQueue.addOperations([outerExecutionBlock]) waitUntilFinished(true);
      
      exit info;
      
    end;
    
        
    method doAuthNoCodeExchange;
    begin
      var issuer: NSURL := issuerURL;
      var redirectURI: NSURL := redirectURL;
      
      NSLog('Fetching configuration for issuer: %@', issuer);
      
      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration:nullable OIDServiceConfiguration; error: nullable NSError)
      begin
        
        if not assigned(configuration) then
        begin
          NSLog('Error retrieving discovery document: %@', error.localizedDescription());
          exit;
        end;
        
        NSLog('Got configuration: %@', configuration);
          
        var request: OIDAuthorizationRequest := new OIDAuthorizationRequest withConfiguration(configuration) clientId(clientID) scopes([OIDScopeOpenID, OIDScopeProfile]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);
        var appDelegate: AuthenticationAppDelegate := (UIApplication.sharedApplication.&delegate) as AuthenticationAppDelegate;
        
        NSLog('Initiating authorization request %@', request);
          
        appDelegate.currentAuthorizationFlow := OIDAuthorizationService.presentAuthorizationRequest(request) presentingViewController(self) callback(method (authorizationResponse: AppAuth.OIDAuthorizationResponse; presentError: NSError)
        begin
            
          if assigned(authorizationResponse) then
          begin
            var authState: OIDAuthState := new OIDAuthState withAuthorizationResponse(authorizationResponse);
            self.setAuthState(authState);
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
      var issuer:NSURL := issuerURL;
      var redirectURI:NSURL := redirectURL;
      
      NSLog('Fetching configuration for issuer: %@', issuer);
      
      OIDAuthorizationService.discoverServiceConfigurationForIssuer(issuer) completion(method (configuration: OIDServiceConfiguration; error: NSError)
      begin
        
        if(not assigned(configuration))then
        begin
          NSLog('Error retrieving discovery document: %@', error.localizedDescription());
          self.setAuthState(nil);
          exit;
        end;
          
        NSLog('Got configuration: %@', configuration);
          
        var request := new OIDAuthorizationRequest withConfiguration(configuration) clientId(clientID) scopes([OIDScopeOpenID, OIDScopeProfile]) redirectURL(redirectURI) responseType(OIDResponseTypeCode) additionalParameters(nil);
            
        var appDelegate: AuthenticationAppDelegate := (UIApplication.sharedApplication.&delegate) as AuthenticationAppDelegate;
        NSLog('Initiating authorization request with scope: %@', request.scope);
          
        appDelegate.currentAuthorizationFlow := OIDAuthState.authStateByPresentingAuthorizationRequest(request)  presentingViewController(self) callback(method (authState: AppAuth.OIDAuthState; authRequestError: NSError)
        begin
            
          if(assigned(authState))then
          begin
            self.setAuthState(authState);
            NSLog('Got authorization tokens. Access token: %@', authState.lastTokenResponse.accessToken);
          end
          else
          begin
            NSLog('Authorization error: %@', authRequestError.localizedDescription());
            self.setAuthState(nil);
          end;
        end);
          
          
      end);
      
    end;
    
    method refresh;
    begin
      
      //if(Expired)then
      if(assigned(_authState))then
      begin
        
        NSLog('current expiry %@',_authState.lastTokenResponse.accessTokenExpirationDate);
        
        var request :OIDTokenRequest := _authState.tokenRefreshRequest;
        
        if(assigned(request))then
        begin
          
          var outerExecutionBlock: NSBlockOperation := NSBlockOperation.blockOperationWithBlock(method
            begin
      
              var semaphore := dispatch_semaphore_create(0);
            
              /*OIDAuthorizationService.*/performTokenRequest(request) callback(method (tokenResponse: AppAuth.OIDTokenResponse; error: NSError)
                begin
                  NSLog('new expiry %@',tokenResponse.accessTokenExpirationDate);
                  
                  _authState.updateWithTokenResponse(tokenResponse) error(error);
                  dispatch_semaphore_signal(semaphore);
                end);
                
              dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);      
                
            end);
            
          var workerQueue := new NSOperationQueue();
          workerQueue.addOperations([outerExecutionBlock]) waitUntilFinished(true);
            
            
        end;
      end;
    end;
    
    property Expired:Boolean read get_Expired;
    
    property Authorized:Boolean read get_Authorized;
    
    class method performTokenRequest(request: OIDTokenRequest) callback(callback: OIDTokenCallback);
    begin
      var urlRequest: NSURLRequest := request.URLRequest();
      var session : NSURLSession := NSURLSession.sharedSession;
      
      var dataTask := session.dataTaskWithRequest(urlRequest) completionHandler((data, response, error) ->
        begin
          if(assigned(error))then
          begin
            callback(nil,error);
          end
          else
          begin
            var httpUrlResponse: NSHTTPURLResponse := NSHTTPURLResponse(response);
            
            if(httpUrlResponse.statusCode <> 200) then
            begin
              var httpError := OIDErrorUtilities.HTTPErrorWithHTTPResponse(httpUrlResponse) data(data);
              callback(nil,httpError);
            end
            else
            begin
              
              var jsonDeserializationError:NSError;
              
              var json := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonDeserializationError);
              
              if(assigned(jsonDeserializationError))then
              begin
              end
              else
              begin
                var tokenResponse := new OIDTokenResponse withRequest(request) parameters(json);
                
                if(not assigned(tokenResponse))then
                begin
                end
                else
                begin
                  callback(tokenResponse,nil);
                end;
                
              end;
              
              
              /*
              NSError *jsonDeserializationError;
              NSDictionary<NSString *, NSObject<NSCopying> *> *json =
              [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonDeserializationError];
              if (jsonDeserializationError) {
              // A problem occurred deserializing the response/JSON.
              NSError *returnedError =
              [OIDErrorUtilities errorWithCode:OIDErrorCodeJSONDeserializationError
              underlyingError:jsonDeserializationError
              description:nil];
              dispatch_async(dispatch_get_main_queue(), ^{
              callback(nil, returnedError);
              });
              return;
              }

              OIDTokenResponse *tokenResponse =
              [[OIDTokenResponse alloc] initWithRequest:request parameters:json];
              if (!tokenResponse) {
              // A problem occurred constructing the token response from the JSON.
              NSError *returnedError =
              [OIDErrorUtilities errorWithCode:OIDErrorCodeTokenResponseConstructionError
              underlyingError:jsonDeserializationError
              description:nil];
              dispatch_async(dispatch_get_main_queue(), ^{
              callback(nil, returnedError);
              });
              return;
              }

              // Success
              dispatch_async(dispatch_get_main_queue(), ^{
              callback(tokenResponse, nil);
              });
              */
              
            end;
          end;
          
        end);
        
      dataTask.resume;

      /*
      + (void)performTokenRequest:(OIDTokenRequest *)request callback:(OIDTokenCallback)callback {
      NSURLRequest *URLRequest = [request URLRequest];
      NSURLSession *session = [NSURLSession sharedSession];
      [[session dataTaskWithRequest:URLRequest
      completionHandler:^(NSData *_Nullable data,
      NSURLResponse *_Nullable response,
      NSError *_Nullable error) {
      if (error) {
      // A network error or server error occurred.
      NSError *returnedError =
      [OIDErrorUtilities errorWithCode:OIDErrorCodeNetworkError
      underlyingError:error
      description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
      callback(nil, returnedError);
      });
      return;
      }

      NSHTTPURLResponse *HTTPURLResponse = (NSHTTPURLResponse *)response;

      if (HTTPURLResponse.statusCode != 200) {
      // A server error occurred.
      NSError *serverError =
      [OIDErrorUtilities HTTPErrorWithHTTPResponse:HTTPURLResponse data:data];

      // HTTP 400 may indicate an RFC6749 Section 5.2 error response, checks for that
      if (HTTPURLResponse.statusCode == 400) {
      NSError *jsonDeserializationError;
      NSDictionary<NSString *, NSObject<NSCopying> *> *json =
      [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonDeserializationError];

      // if the HTTP 400 response parses as JSON and has an 'error' key, it's an OAuth error
      // these errors are special as they indicate a problem with the authorization grant
      if (json[OIDOAuthErrorFieldError]) {
      NSError *oauthError =
      [OIDErrorUtilities OAuthErrorWithDomain:OIDOAuthTokenErrorDomain
      OAuthResponse:json
      underlyingError:serverError];
      dispatch_async(dispatch_get_main_queue(), ^{
      callback(nil, oauthError);
      });
      return;
      }
      }

      // not an OAuth error, just a generic server error
      NSError *returnedError =
      [OIDErrorUtilities errorWithCode:OIDErrorCodeServerError
      underlyingError:serverError
      description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
      callback(nil, returnedError);
      });
      return;
      }
      */
      
    
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
