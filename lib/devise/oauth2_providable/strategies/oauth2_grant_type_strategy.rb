# -*- encoding: utf-8 -*-
require 'devise/strategies/base'

module Devise
  module Strategies
    class Oauth2GrantTypeStrategy < Authenticatable

      def valid?
        params[:controller] == 'devise/oauth2_providable/tokens' && request.post? && params[:grant_type] == grant_type
      end

      # defined by subclass
      def grant_type
      end

      # defined by subclass
      def authenticate_grant_type(client)
      end

      def authenticate!
        app_id = params[:app_id] || params[:client_id]
        app_key = params[:app_key] || params[:client_secret]
        client_id, client_secret = request.authorization ? decode_credentials : [app_id, app_key]
        client = Devise::Oauth2Providable::Client.find_by_identifier client_id
        if client && client.secret == client_secret
          env[Devise::Oauth2Providable::CLIENT_ENV_REF] = client
          authenticate_grant_type(client)
        else
          oauth_error! :invalid_client, '请求证书不正确。'
        end
        
      end

      # return custom error response in accordance with the oauth spec
      # see http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-4.3
      def oauth_error!(error_code = :invalid_request, description = nil)
        body = {:errors=>{:message=>description,:status_code=>error_code}}
        # body[:error_description] = description if description
        custom! [400, {'Content-Type' => 'application/json'}, [body.to_json]]
        throw :warden
      end
    end
  end
end
