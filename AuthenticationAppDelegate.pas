namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation,UIKit;
  
type

  AuthenticationAppDelegate = public class(IUIApplicationDelegate)
  public
  
    method application(app: UIApplication) openURL(url: NSURL) options(options: NSDictionary<NSString, id>): Boolean;
    begin
      //if((assigned(self.currentAuthorizationFlow)) and (self.currentAuthorizationFlow is IOIDAuthorizationFlowSession))then
      //begin
      if IOIDAuthorizationFlowSession(currentAuthorizationFlow).resumeAuthorizationFlowWithURL(url) then
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
    
    property currentAuthorizationFlow: IOIDAuthorizationFlowSession;
    
  
  end;
  

end.
