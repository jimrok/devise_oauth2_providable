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

        if CONFIG[:ldap] == "on" then
            if(res['Set-Cookie'] && res['Set-Cookie'].start_with?("ObSSOCookie=")) then
              sso_cookie = res['Set-Cookie'].split(";").first.split("=").last
              cookies[:ObSSOCookie] = { :value =>sso_cookie}
              user_entry = LdapHelper.search_user_entry_by_oa_name(username)
              cookies[:orgid] = user_entry[:o]

              user = User.joins(:user_info).where("(user_infos.cellvoice1 = #{user_entry[:mobile][0]} or user_infos.cellvoice2 = #{user_entry[:mobile][0]}) and actived=true and suspended=0").first
              
              if user then
                  org_id = user_entry[:o].first
                  $redis.setex "user_cookie:#{user.id}", CONFIG[:oa_timeout], sso_cookie
                  $redis.setex "user_org_id:#{user.id}", CONFIG[:oa_timeout], org_id              
                  success! user.account
              else
                  oauth_error! :invalid_grant, '该用户不存在'
              end
            elsif res.code[0].in? ["4","5"] then
              oauth_error! :invalid_grant, 'OA认证服务器异常'
            else
              oauth_error! :invalid_grant, '用户名或密码错误'
            end
        else
            resource = mapping.to.find_for_authentication(mapping.to.authentication_keys.first => params[:username])
            if validate(resource) { resource.valid_password?(params[:password]) }
              success! resource
            else
              oauth_error! :invalid_grant, "用户名或密码错误."
            end
        end

      end
    end
  end
end

Warden::Strategies.add(:js_oa_account_grantable, Devise::Strategies::JsOaAccountGrantTypeStrategy)