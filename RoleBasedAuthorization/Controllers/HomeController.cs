using RoleBasedAuthorization.App_Code;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using RoleBasedAuthorization.Models;
using System.Web.Security;

namespace RoleBasedAuthorization.Controllers
{
    public class HomeController : Controller
    {
        LabEntities db = new LabEntities();
        protected string username;

        protected override void Initialize(System.Web.Routing.RequestContext requestContext)
        {
            base.Initialize(requestContext);

            if (requestContext.HttpContext.User.Identity.IsAuthenticated)
                username = requestContext.HttpContext.User.Identity.Name;
        }

        [Authorize]
        public ActionResult Index() => View(db.RoleBasedAuthorizationMembers.First(o => o.Mbr_ID == username));

        [Authorize(Roles = "user")]
        public ActionResult About() => View();

        [Authorize(Roles = "admin")]
        public ActionResult Contact() => View();

        public ActionResult Login()
        {
            //如果已經登入則導到首頁
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");
            else
                return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string uid, string pwd)
        {
            if (!ModelState.IsValid)
                return Content("請填寫所有欄位");
            Tools t = new Tools();
            pwd = t.SHA512(pwd);
            if (db.RoleBasedAuthorizationMembers.Count(o => o.Mbr_ID == uid) == 1)
            {
                var mbr = db.RoleBasedAuthorizationMembers.FirstOrDefault(o => o.Mbr_ID == uid);
                if (!(bool)mbr.Mbr_Enabled)
                    return Content("帳號已停權");
                if (mbr.Mbr_Pwd == pwd)
                {
                    LoginProcess(uid, mbr.Mbr_Role);
                    return Json(true);
                }
            }
            return Content("帳號或密碼錯誤");
        }


        /// <summary>
        /// 取得登入認證
        /// </summary>
        private void LoginProcess(string uid, string role)
        {
            var now = DateTime.Now;
            var ticket = new FormsAuthenticationTicket(
                version: 1,
                name: uid,
                issueDate: now,
                expiration: now.AddYears(1),
                isPersistent: false,
                userData: role,
                cookiePath: FormsAuthentication.FormsCookiePath);
            var encryptedTicket = FormsAuthentication.Encrypt(ticket);
            var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
            //cookie.Expires = DateTime.Now.AddDays(7);
            Response.Cookies.Add(cookie);
        }


        /// <summary>
        /// 登出
        /// </summary>
        /// <returns></returns>
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            //清除所有的 session
            Session.RemoveAll();

            //建立一個同名的 Cookie 來覆蓋原本的 Cookie
            HttpCookie cookie1 = new HttpCookie(FormsAuthentication.FormsCookieName, "");
            cookie1.Expires = DateTime.Now.AddYears(-1);
            Response.Cookies.Add(cookie1);
            //建立 ASP.NET 的 Session Cookie 同樣是為了覆蓋
            return RedirectToAction("Login", "Home");
        }

    }
}