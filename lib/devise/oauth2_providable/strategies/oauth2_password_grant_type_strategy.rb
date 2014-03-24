# -*- encoding: utf-8 -*-
require 'devise/oauth2_providable/strategies/oauth2_grant_type_strategy'

module Devise
  module Strategies
    class Oauth2PasswordGrantTypeStrategy < Oauth2GrantTypeStrategy
      def grant_type
        'password'
      end

      def authenticate_grant_type(client)
        login_name = params[:login_name] || params[:username]

        warden = request.env['warden']
        warden.authenticate(:password_authenticatable)
        resource = warden.user(:account)

        
        if validate(resource) { !resource.nil? }
          success! resource
        else
          oauth_error! :invalid_grant, "用户名或密码错误."
        end
      end
    end
  end
end

Warden::Strategies.add(:oauth2_password_grantable, Devise::Strategies::Oauth2PasswordGrantTypeStrategy)
