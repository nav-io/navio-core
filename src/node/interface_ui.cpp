// Copyright (c) 2010-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/interface_ui.h>

#include <util/string.h>
#include <util/translation.h>

#include <btcsignals.h>

CClientUIInterface uiInterface;

struct UISignals {
    btcsignals::signal<CClientUIInterface::ThreadSafeMessageBoxSig, btcsignals::optional_last_value<bool>> ThreadSafeMessageBox;
    btcsignals::signal<CClientUIInterface::ThreadSafeQuestionSig, btcsignals::optional_last_value<bool>> ThreadSafeQuestion;
    btcsignals::signal<CClientUIInterface::InitMessageSig> InitMessage;
    btcsignals::signal<CClientUIInterface::NotifyBlockTipSig> NotifyBlockTip;
};
static UISignals g_ui_signals;

#define ADD_SIGNALS_IMPL_WRAPPER(signal_name)                                                                 \
    btcsignals::connection CClientUIInterface::signal_name##_connect(std::function<signal_name##Sig> fn) \
    {                                                                                                         \
        return g_ui_signals.signal_name.connect(fn);                                                          \
    }

ADD_SIGNALS_IMPL_WRAPPER(ThreadSafeMessageBox);
ADD_SIGNALS_IMPL_WRAPPER(ThreadSafeQuestion);
ADD_SIGNALS_IMPL_WRAPPER(InitMessage);
ADD_SIGNALS_IMPL_WRAPPER(NotifyBlockTip);

bool CClientUIInterface::ThreadSafeMessageBox(const bilingual_str& message, const std::string& caption, unsigned int style) { return g_ui_signals.ThreadSafeMessageBox(message, caption, style).value_or(false);}
bool CClientUIInterface::ThreadSafeQuestion(const bilingual_str& message, const std::string& non_interactive_message, const std::string& caption, unsigned int style) { return g_ui_signals.ThreadSafeQuestion(message, non_interactive_message, caption, style).value_or(false);}
void CClientUIInterface::InitMessage(const std::string& message) { return g_ui_signals.InitMessage(message); }
void CClientUIInterface::NotifyBlockTip(SynchronizationState s, const CBlockIndex* i) { return g_ui_signals.NotifyBlockTip(s, i); }

bool InitError(const bilingual_str& str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_ERROR);
    return false;
}

bool InitError(const bilingual_str& str, const std::vector<std::string>& details)
{
    // For now just flatten the list of error details into a string to pass to
    // the base InitError overload. In the future, if more init code provides
    // error details, the details could be passed separately from the main
    // message for rich display in the GUI. But currently the only init
    // functions which provide error details are ones that run during early init
    // before the GUI uiInterface is registered, so there's no point passing
    // main messages and details separately to uiInterface yet.
    return InitError(details.empty() ? str : strprintf(Untranslated("%s:\n%s"), str, MakeUnorderedList(details)));
}

void InitWarning(const bilingual_str& str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_WARNING);
}
