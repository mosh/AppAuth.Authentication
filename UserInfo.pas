namespace AppAuth.Authentication;

uses
  Foundation;
  
type

  UserInfo = public class
  public
    property FamilyName:String;
    property Gender:String;
    property GivenName:String;
    property Name:String;
    property Picture:String;
    property Locale:String;
    property Email:String;
  end;

end.
