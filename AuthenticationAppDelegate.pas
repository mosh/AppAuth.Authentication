namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation,UIKit;

type

  AuthenticationAppDelegate = public class(IUIApplicationDelegate)
  private
    _authenticationService:AuthenticationService;

  public
    property InAuthorizationFlow:Boolean;

    method application(app: UIApplication) openURL(url: NSURL) options(options: NSDictionary<NSString, id>): Boolean;
    begin
      if currentAuthorizationFlow.resumeExternalUserAgentFlowWithURL(url) then
      begin
        currentAuthorizationFlow := nil;
        exit true;
      end;
      //end;
      exit false;
    end;

    method application(application: UIApplication) openURL(url: NSURL) sourceApplication(sourceApplication: NSString) annotation(annotation: id): Boolean;
    begin
      var options := new NSDictionary<NSString, id>;
      exit self.application(application) openURL(url) options(options);
    end;

    // The authorization flow session which receives the return URL from \SFSafariViewController.
    // We need to store this in the app delegate as it's that delegate which receives the
    // incoming URL on UIApplicationDelegate.application:openURL:options:. This property will be
    // nil, except when an authorization flow is in progress.
    property currentAuthorizationFlow: OIDExternalUserAgentSession;

    property AuthenticationService:AuthenticationService read
      begin
        if(not assigned(_authenticationService))then
        begin
          _authenticationService := new AuthenticationService;
        end;
        exit _authenticationService;
      end;


  end;


end.