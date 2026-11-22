// Package notifier distributes log messages to several outputs (log file,
// syslog, e-mail, standard output, callback functions).
//
// A Notifier runs a dispatcher goroutine. Messages sent with Send or Attach
// are filtered by severity and forwarded to every registered output, each of
// which runs in its own goroutine and receives messages over a channel.
//
// # Writing a new output
//
// An output implements the Output interface: Run reads messages from the
// channel until it is closed and then returns. Besides normal messages
// (MSGTYPE_MESSAGE, MSGTYPE_ATTACHMENT) it receives MSGTYPE_FLUSH (deliver
// buffered data, sent by Notifier.Flush) and MSGTYPE_REOPEN (reopen files or
// connections, sent by Notifier.Reopen). Closing the channel is the end
// signal: finish pending work, then return. Notifier.Close waits for that.
//
// The severity filter is applied by the Notifier. An output may implement
// MsgFilter to opt out of attachments or flush messages; without it, all
// message types are delivered.
//
//	type webhookOutput struct{ url string }
//
//	func (w *webhookOutput) Run(ch <-chan *notifier.Msg) {
//		for m := range ch {
//			if m.MsgType == notifier.MSGTYPE_MESSAGE {
//				post(w.url, m.String())
//			}
//		}
//	}
//
//	// only deliver messages, no attachments or flush requests:
//	func (w *webhookOutput) Accepts(t notifier.MsgType) bool {
//		return t == notifier.MSGTYPE_MESSAGE
//	}
//
//	n := notifier.New()
//	err := n.AddOutput(notifier.WARNING, &webhookOutput{url: "https://example.org/hook"})
//
// Messages at WARNING or more important are then delivered to the output.
// The existing AddLogger* methods are thin wrappers around AddOutput.
package notifier
