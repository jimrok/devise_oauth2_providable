# -*- encoding: utf-8 -*-
require 'devise/oauth2_providable/strategies/oauth2_grant_type_strategy'

module Devise
  module Strategies
    class Oauth2RefreshTokenGrantTypeStrategy < Oauth2GrantTypeStrategy
      def grant_type
        'refresh_token'
      end

      def authenticate_grant_type(client)
        if refresh_token = client.refresh_tokens.find_by_token(params[:refresh_token])
          env[Devise::Oauth2Providable::REFRESH_TOKEN_ENV_REF] = refresh_token
          success! refresh_token.account
        else
          error_message="您的账号已过期，请重新登录。"
          account_id=params[:account_id]
          if(account_id) then
            device = ApnDevice.where(:account_id=>account_id).order("updated_at desc").first()
            unless device.nil?
              error_message="您的账号已于#{device.updated_at.localtime.strftime("%Y-%m-%d %H:%M")}在其它地方登录。登录设备是#{device.device_name}，请注意账号安全。" 
            end
          end
          oauth_error! :invalid_grant, error_message
        end
      end
    end
  end
end

Warden::Strategies.add(:oauth2_refresh_token_grantable, Devise::Strategies::Oauth2RefreshTokenGrantTypeStrategy)
