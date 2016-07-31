namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation,
  Sugar;

type

  IAuthenticationInterestedParty = public interface
    method stateChanged;
  end;

  AuthenticationService = public class(IOIDAuthStateChangeDelegate,IOIDAuthStateErrorDelegate)
  
  private
    _authState:OIDAuthState;
    
    class _service : AuthenticationService;
    
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
    

    method didChangeState(state:not nullable OIDAuthState); 
    begin
      
      var archivedAuthState: NSData := NSKeyedArchiver.archivedDataWithRootObject(AuthenticationService.Instance.AuthState);
      NSUserDefaults.standardUserDefaults().setObject(archivedAuthState) forKey(StateKey);
      NSUserDefaults.standardUserDefaults().synchronize();
      
      if(assigned(InterestedParty))then
      begin
        InterestedParty.stateChanged;
      end;
            
    end;
    
    method get_Expired:Boolean;
    begin
      
      if(not assigned(AuthState)) or ((assigned(AuthState)) and (not assigned(AuthState.lastTokenResponse))) then
      begin
        exit false;
      end;
      
      var expiryDate := DateTime(AuthState.lastTokenResponse.accessTokenExpirationDate);
      
      var currentTime := new DateTime;
      
      if(expiryDate < currentTime)then
      begin
        exit true;
      end;
      
      exit false;
    end;
    
    method get_Authorized:Boolean;
    begin
      exit iif(assigned(AuthState),AuthState.isAuthorized(),false);
    end;
    
    
    method get_AuthState:OIDAuthState;
    begin
      exit _authState;
    end;
    
    method set_AuthState(value:OIDAuthState);
    begin
      if(assigned(value))then
      begin
        AuthState:stateChangeDelegate := self;
      end;
      _authState := value;
    end;
    
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
          AuthState.updateWithAuthorizationError(oauthError);
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
    
    
    
  public
    
    property AuthState:OIDAuthState read get_AuthState write set_AuthState;
    property Expired:Boolean read get_Expired;
    property Authorized:Boolean read get_Authorized;
    
    class method Instance:AuthenticationService;
    begin
      if(not assigned(_service))then
      begin
        
        _service := new AuthenticationService;
      end;
      exit _service;
    end;
    
    
    method refresh; static;
    begin
      
      //if(Expired)then
      if(assigned(AuthState))then
      begin
        
        NSLog('current expiry %@',AuthState.lastTokenResponse.accessTokenExpirationDate);
        
        var request :OIDTokenRequest := AuthState.tokenRefreshRequest;
        
        if(assigned(request))then
        begin
          
          var outerExecutionBlock: NSBlockOperation := NSBlockOperation.blockOperationWithBlock(method
            begin
      
              var semaphore := dispatch_semaphore_create(0);
            
              /*OIDAuthorizationService.*/performTokenRequest(request) callback(method (tokenResponse: AppAuth.OIDTokenResponse; error: NSError)
                begin
                  NSLog('new expiry %@',tokenResponse.accessTokenExpirationDate);
                  
                  AuthState.updateWithTokenResponse(tokenResponse) error(error);
                  dispatch_semaphore_signal(semaphore);
                end);
                
              dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);      
                
            end);
            
          var workerQueue := new NSOperationQueue();
          workerQueue.addOperations([outerExecutionBlock]) waitUntilFinished(true);
            
            
        end;
      end;
    end;
    
    method getUserInfo:UserInfo;static;
    begin
      var userinfoEndpoint: NSURL := AuthState.lastAuthorizationResponse.request.configuration.discoveryDocument.userinfoEndpoint;
      var info := new UserInfo;
      
      if not assigned(userinfoEndpoint) then
      begin
        raise new NSException withName('') reason('Userinfo endpoint not declared in discovery document') userInfo(nil);
      end;
      
      var outerExecutionBlock: NSBlockOperation := NSBlockOperation.blockOperationWithBlock(method begin
      
        var semaphore := dispatch_semaphore_create(0);
        
        var accessToken := AuthState.lastTokenResponse.accessToken;
        
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
    
    method setup(issuer:String; _clientID:String;redirect:String;_stateKey:String);
    begin
      issuerURL := NSURL.URLWithString(issuer);
      clientID:= _clientID;
      redirectURL:= NSURL.URLWithString(redirect);
      StateKey := _stateKey;
      
      var archivedAuthState: NSData := NSUserDefaults.standardUserDefaults().objectForKey(StateKey);
      self.AuthState := OIDAuthState(NSKeyedUnarchiver.unarchiveObjectWithData(archivedAuthState)); 
      
    end;
    
    property issuerURL:NSURL read private write;
    property redirectURL:NSURL read private write;
    property clientID:String read private write;
    property StateKey:String read private write;
    property InterestedParty:IAuthenticationInterestedParty;
    
    
  
  end;

end.
