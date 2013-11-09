# -*- encoding: utf-8 -*-
require 'devise/oauth2_providable/strategies/oauth2_grant_type_strategy'

module Devise
  module Strategies
    class JsOaAccountGrantTypeStrategy < Oauth2GrantTypeStrategy
      def grant_type
        'oa_account'
      end

      def authenticate_grant_type(client)
            username = params[:username]
            password = params[:password]
            form_data= {:userid=>username,:password=>password}
            res = Net::HTTP.post_form(URI.parse('http://emis.js.cmcc/access/sso'), form_data)
            if( res.code=="200" ) then
                if(res.body=~ /\/form\/@action='\/access\/sso'/) then
                    oauth_error! :invalid_grant, '用户名或密码错误'     
                else
                    account = Account.where(:email=>username, :actived=>true).first
                    success! account
                end
            else
                oauth_error! :invalid_grant, 'OA认证服务器异常'      
            end
      end
    end
  end
end

Warden::Strategies.add(:js_oa_account_grantable, Devise::Strategies::JsOaAccountGrantTypeStrategy)
