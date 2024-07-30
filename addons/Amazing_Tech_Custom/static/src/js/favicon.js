/** @odoo-module **/

import { WebClient } from "@web/webclient/webclient";
import { patch } from "web.utils";

patch(WebClient.prototype, "Amazing_Tech_Custom.WebClient", {
    setup() {
        this._super();
        this.title.setParts({ zopenerp: "AmazingTech" });
    },
});