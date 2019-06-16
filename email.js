const nodemailer = require('nodemailer');

class Email{
    constructor(oconfig){
        this.createTransport = nodemailer.createTransport(oconfig);
    }

    sendMail(oemail){
       return new Promise((resolve, reject) => {
           try {
               this.createTransport.sendMail(oemail, (err, inf) => {
                   if (err) {
                       reject(err);
                   } else {
                      resolve(inf);
                   }

               })
           } catch (error) {
               reject(error)
           }
       })
    }
}

module.exports = Email;