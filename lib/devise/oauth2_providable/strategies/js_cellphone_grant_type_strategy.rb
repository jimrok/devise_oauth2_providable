require 'devise/oauth2_providable/strategies/oauth2_grant_type_strategy'

module Devise
  module Strategies
    class JsCellphoneGrantTypeStrategy < Oauth2GrantTypeStrategy
      def grant_type
        'cellphone'
      end

      def authenticate_grant_type(client)
        cellphone = params[:username]
        verification_code = params[:password]
        if cellphone.present? 
            last_sender = SmsAuthSender.find_not_valid_sender(cellphone, verification_code)
            if last_sender
                if ((Time.now - last_sender.created_at) > 300) then
                    oauth_error! :invalid_grant, 'invalid verification_code'
                else
                    user = last_sender.valid_auth!
                    if user
                        success! user.account
                    else
                        oauth_error! :invalid_grant, 'invalid cellphone authentication request'
                    end
                end
            else
                oauth_error! :invalid_grant, 'invalid cellphone authentication request'
            end
        else
            oauth_error! :invalid_grant, 'invalid password authentication request'
        end
      end
    end
  end
end

Warden::Strategies.add(:js_cellphone_grantable, Devise::Strategies::JsCellphoneGrantTypeStrategy)
