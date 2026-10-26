package tgapi_test

import (
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func TestClassify(t *testing.T) {
	tests := map[tgapi.Class][]string{
		tgapi.Safe: {
			"getMe", "getUpdates", "getFile", "getChat", "getChatMember", "getMyCommands", "getWebhookInfo",
			"setMyCommands", "setChatTitle", "setMessageReaction", "setChatPermissions", "setGameScore",
			"deleteMessage", "deleteMessages", "deleteWebhook", "deleteMyCommands", "deleteForumTopic",
			"pinChatMessage", "unpinChatMessage", "unpinAllChatMessages",
			"banChatMember", "unbanChatMember", "banChatSenderChat", "restrictChatMember", "promoteChatMember",
		},
		tgapi.Semi: {
			"editMessageText", "editMessageCaption", "editMessageMedia", "editMessageReplyMarkup",
			"editMessageLiveLocation", "editForumTopic", "editChatInviteLink",
			"answerCallbackQuery", "answerInlineQuery", "answerShippingQuery", "answerPreCheckoutQuery", "answerWebAppQuery",
			"stopPoll", "sendChatAction", "stopMessageLiveLocation",
		},
		tgapi.Unsafe: {
			"sendMessage", "sendPhoto", "sendDocument", "sendMediaGroup", "sendPoll", "sendInvoice", "sendDice",
			"forwardMessage", "forwardMessages", "copyMessage", "copyMessages",
			"createForumTopic", "createInvoiceLink", "createChatInviteLink", "createNewStickerSet",
			"refundStarPayment", "setWebhook", "leaveChat", "approveChatJoinRequest", "transferGift",
			"definitelyUnknown", "", "x",
		},
	}
	for class, methods := range tests {
		for _, m := range methods {
			if got := tgapi.Classify(m); got != class {
				t.Errorf("Classify(%q) = %v, want %v", m, got, class)
			}
		}
	}
}

func TestClassifyCaseInsensitive(t *testing.T) {
	for _, m := range []string{"SendMessage", "SENDMESSAGE", "sendmessage"} {
		if tgapi.Classify(m) != tgapi.Unsafe {
			t.Errorf("%s must be unsafe", m)
		}
	}
	if tgapi.Classify("EDITMESSAGETEXT") != tgapi.Semi || tgapi.Classify("GetMe") != tgapi.Safe {
		t.Error("case-insensitivity broken")
	}
	if tgapi.Classify("SETWEBHOOK") != tgapi.Unsafe {
		t.Error("setWebhook must not be safe")
	}
}

func TestAllKnownMethodsClassified(t *testing.T) {
	// every send*/forward*/copy*/create*/refund* known method must be Unsafe
	for _, m := range knownList(t) {
		c := tgapi.Classify(m)
		for _, p := range []string{"send", "forward", "copy", "create", "refund"} {
			if len(m) >= len(p) && m[:len(p)] == p && m != "sendchataction" && c != tgapi.Unsafe {
				t.Errorf("%s classified %v", m, c)
			}
		}
	}
}

func TestClassString(t *testing.T) {
	if tgapi.Safe.String() != "safe" || tgapi.Semi.String() != "semi" || tgapi.Unsafe.String() != "unsafe" {
		t.Fatal("labels")
	}
}

func TestWebhookAndLongPoll(t *testing.T) {
	if !tgapi.IsWebhookSetter("setWebhook") || !tgapi.IsWebhookSetter("SETWEBHOOK") || tgapi.IsWebhookSetter("deleteWebhook") {
		t.Fatal("IsWebhookSetter")
	}
	if !tgapi.IsLongPoll("getUpdates") || !tgapi.IsLongPoll("GETUPDATES") || tgapi.IsLongPoll("getMe") {
		t.Fatal("IsLongPoll")
	}
}
