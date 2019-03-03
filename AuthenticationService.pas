namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation,RemObjects.Elements.RTL;

type


  AuthenticationService = public class(IOIDAuthStateChangeDelegate,IOIDAuthStateErrorDelegate)

  private
    _authState:OIDAuthState;

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

    method saveState(state:OIDAuthState);
    begin
      var archivedAuthState: NSData := NSKeyedArchiver.archivedDataWithRootObject(state);
      NSUserDefaults.standardUserDefaults().setObject(archivedAuthState) forKey(StateKey);
      NSUserDefaults.standardUserDefaults().synchronize();
    end;

    method didChangeState(state:not nullable OIDAuthState);
    begin

      saveState(state);

      var userinfoEndpoint: NSURL := state.lastAuthorizationResponse.request.configuration.discoveryDocument.userinfoEndpoint;

      if not assigned(userinfoEndpoint) then
      begin
        raise new NSException withName('') reason('Userinfo endpoint not declared in discovery document') userInfo(nil);
      end;

      var lastAccessToken := state.lastTokenResponse.accessToken;
      var error:NSError;
      var info := UserInfoHelper.getUserInfo(lastAccessToken, userinfoEndpoint, error);

      if(assigned(error))then
      begin
        state.updateWithAuthorizationError(error);
        &delegate:stateChanged(nil);
      end;

      &delegate:stateChanged(info);

    end;


    class method performTokenRequest(request: OIDTokenRequest) callback(callback: OIDTokenCallback);
    begin
      var urlRequest: NSURLRequest := request.URLRequest();
      var session : NSURLSession := NSURLSession.sharedSession;

      var dataTask := session.dataTaskWithRequest(urlRequest) completionHandler((data, response, error) ->
        begin
          if(assigned(error))then
          begin
            var returnedError: NSError := OIDErrorUtilities.errorWithCode(OIDErrorCode.NetworkError) underlyingError(error) description(nil);
            callback(nil,returnedError);
          end
          else
          begin
            var httpUrlResponse: NSHTTPURLResponse := NSHTTPURLResponse(response);

            if(httpUrlResponse.statusCode <> 200) then
            begin

              // A server error occurred.
              var serverError : NSError := OIDErrorUtilities.HTTPErrorWithHTTPResponse(httpUrlResponse) data(data);

              // HTTP 400 may indicate an RFC6749 Section 5.2 error response, checks for that
              if (httpUrlResponse.statusCode = 400) then
              begin
                var jsonDeserializationError:NSError;

                var json := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonDeserializationError);

                // if the HTTP 400 response parses as JSON and has an 'error' key, it's an OAuth error
                // these errors are special as they indicate a problem with the authorization grant
                if (json[OIDOAuthErrorFieldError]) then
                begin
                  var oAuthError:NSError := OIDErrorUtilities.OAuthErrorWithDomain(OIDOAuthTokenErrorDomain) OAuthResponse(json) underlyingError(serverError);
                  callback(nil, oAuthError);
                  exit;
                end;
              end;

              // not an OAuth error, just a generic server error
              var returnedError:NSError := OIDErrorUtilities.errorWithCode(OIDErrorCode.ServerError) underlyingError(serverError) description(nil);
              callback(nil,returnedError);
              exit;
            end
            else
            begin

              var jsonDeserializationError:NSError;

              var json := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonDeserializationError);

              if(assigned(jsonDeserializationError))then
              begin
                var returnedError: NSError := OIDErrorUtilities.errorWithCode(OIDErrorCode.JSONDeserializationError) underlyingError(jsonDeserializationError) description(nil);
                callback(nil, returnedError);
              end
              else
              begin
                var tokenResponse := new OIDTokenResponse withRequest(request) parameters(json);

                if(not assigned(tokenResponse))then
                begin
                  var returnedError: NSError := OIDErrorUtilities.errorWithCode(OIDErrorCode.TokenResponseConstructionError) underlyingError(jsonDeserializationError) description(nil);
                  callback(nil, returnedError);
                end
                else
                begin
                  callback(tokenResponse,nil);
                end;
              end;
            end;
          end;

        end);

      dataTask.resume;
    end;

  public

    property AuthState:OIDAuthState read begin
        exit _authState;
      end
      write begin
        if(assigned(value))then
        begin
          value.stateChangeDelegate := self;
        end;
        _authState := value;

        var info:UserInfo := nil;

        if(assigned(_authState))then
        begin

          var userinfoEndpoint: NSURL := _authState.lastAuthorizationResponse.request.configuration.discoveryDocument.userinfoEndpoint;

          if not assigned(userinfoEndpoint) then
          begin
            raise new NSException withName('') reason('Userinfo endpoint not declared in discovery document') userInfo(nil);
          end;

          var lastAccessToken := _authState.lastTokenResponse.accessToken;

          var error:NSError;

          info := UserInfoHelper.getUserInfo(lastAccessToken, userinfoEndpoint, error);

          if(assigned(error))then
          begin
            _authState.updateWithAuthorizationError(error);
            &delegate:stateChanged(nil);
          end;

        end;

        saveState(value);

        &delegate:stateChanged(info);
      end;

    property Expired:Boolean read begin

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


    property Authorized:Boolean read begin
      var _authorized := iif(assigned(AuthState),AuthState.isAuthorized(),false);
      if(not _authorized)then
      begin
        NSLog('AuthenticationService: Not Authorized');
      end;
      exit _authorized;
    end;

    method refresh;
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
                  if(assigned(tokenResponse))then
                  begin
                    NSLog('new expiry %@',tokenResponse.accessTokenExpirationDate);
                  end
                  else
                  begin
                    NSLog('%@','tokenResponse not assigned');
                  end;

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


    method setup(issuer:String; _clientID:String;redirect:String;_stateKey:String);
    begin
      issuerURL := NSURL.URLWithString(issuer);
      clientID:= _clientID;
      redirectURL:= NSURL.URLWithString(redirect);
      StateKey := _stateKey;

      var archivedAuthState: NSData := NSUserDefaults.standardUserDefaults().objectForKey(StateKey);
      self._authState := OIDAuthState(NSKeyedUnarchiver.unarchiveObjectWithData(archivedAuthState));
      self._authState:stateChangeDelegate := self;

    end;

    property issuerURL:NSURL read private write;
    property redirectURL:NSURL read private write;
    property clientID:String read private write;
    property StateKey:String read private write;
    property &delegate:IAuthenticationInterestedParty;

    property AccessToken:String read begin
      var _accessToken := iif(Authorized,AuthState.lastTokenResponse.accessToken,'');
      NSLog('AuthenticationService AccessToken [%@]',_accessToken);
      exit _accessToken;
    end;



    method clear;
    begin
      AuthState := nil;
    end;

  end;

end.