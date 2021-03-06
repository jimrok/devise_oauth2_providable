require 'devise/strategies/base'

module Devise
  module Strategies
    class Oauth2Providable < Authenticatable
      def valid?
        @req = Rack::OAuth2::Server::Resource::Bearer::Request.new(env)
        @req.oauth2?
      end
      def authenticate!
        
        @req.setup!
        token = Devise::Oauth2Providable::AccessToken.find_by_token @req.access_token
        env[Devise::Oauth2Providable::CLIENT_ENV_REF] = token.client if token
        resource = token ? token.user : nil
        if validate(resource)
          success! resource
        else
          Rails.logger.error "Oauth2 create token error: invalid_token."
          fail(:invalid_token)
        end
      end
    end
  end
end

Warden::Strategies.add(:oauth2_providable, Devise::Strategies::Oauth2Providable)
