"""Does the request text actually authorise deletion?  (multilingual, rule based, deterministic)

The lexicon below is the only intent logic; no model is called at run time.
"""
from __future__ import annotations

import re
from typing import Tuple

# positive deletion cues (English + es/pt/fr/de/it/ja/ko/zh)
DELETE_CUES = [
    r"\bdelet\w*", r"\berase\w*", r"\berasure\b", r"\bpermanently remov\w*", r"\bremov\w* (?:my|the|this) (?:account|profile|personal|data)",
    r"\bclos\w* (?:my|this|the) account", r"\baccount[^.]{0,40}\bclosed\b", r"\bwipe\b", r"\bpurge\b",
    r"\bclose (?:it|the account)\b", r"\bremove (?:my )?account\b", r"\bdestroy\b",
    r"elimin\w+", r"\bborr\w+", r"exclu[ií]\w*", r"exclus[aã]o", r"\bapag\w+", r"supprim\w+", r"suppression", r"\beffac\w+",
    r"\blösch\w+", r"löschung", r"\bcancell?\w* (?:la|el|mi) cuenta", r"cancelar (?:a|minha) conta", r"\bcancella\w*", r"\belimina\w*",
    r"削除", r"消去", r"退会", r"삭제", r"탈퇴", r"删除", r"注销",
]
# requests that are explicitly about something else
OTHER_CUES = [
    r"opt[- ]?out", r"unsubscribe", r"marketing lists?", r"promotional", r"newsletter", r"stop (?:the )?(?:\w+ )?emails",
    r"download (?:my|the|a) ", r"portable format", r"copy of", r"what personal information", r"tell me what (?:personal|data)",
    r"misspell", r"out of date", r"outdated", r"change the email", r"change (?:my )?(?:email|phone|name|address)",
    r"reset(?:ting)? (?:the|my) ", r"can't access", r"cannot access", r"invoices?", r"correct (?:it|the (?:spelling|name|surname))",
]
# statements that the person wants to KEEP the account / records
KEEP = [
    r"(?:keep|leave|retain|preserve|maintain) (?:the|my|this) (?:account|profile|records?|purchase|order)",
    r"(?:keep|leave) (?:it|them) as (?:it|they) (?:is|are)", r"still (?:need|use|want)", r"without (?:removing|deleting|closing)",
    r"(?:do not|don't|dont|never) (?:delete|erase|remove|close)", r"not (?:ask|asking|requesting) (?:for )?(?:a )?(?:the )?(?:account )?(?:deletion|removal)",
    r"continue using", r"no (?:deletion|me elimine)",
    r"not (?:a )?(?:request|asking) (?:to|for) (?:erase|delet|remov|clos)", r"information request",
    r"(?:do not|don't|dont|never) (?:want|wish|need|intend|ask) (?:you )?(?:to )?(?:delete|erase|remove|close)",
    # negated deletion verbs in other languages ("I do not want to delete ...")
    r"\bno (?:quiero|deseo|pido|solicito|estoy pidiendo) (?:que )?(?:\w+ )?(?:eliminar|borrar|cerrar|cancelar)",
    r"\bn[aã]o (?:quero|desejo|pe[cç]o|estou pedindo) (?:\w+ )?(?:excluir|apagar|eliminar|encerrar|cancelar)",
    r"\bne (?:veux|souhaite|demande) pas (?:\w+ )?(?:supprimer|effacer|fermer|clôturer)",
    r"\bnicht (?:\w+ )?(?:löschen|schließen|entfernen)", r"\bkeine (?:löschung|kündigung)",
    r"\bnon (?:voglio|desidero|chiedo) (?:\w+ )?(?:eliminare|cancellare|chiudere)",
    r"削除(?:は|を)?(?:希望|お願い)?(?:しません|しないで|不要)", r"삭제(?:하지|를 원하지)", r"不(?:要|想|需要)(?:删除|注销)",
]


def authorizes_deletion(text: str) -> Tuple[bool, str]:
    """Return (authorised, reason).

    Default is *authorised*: in this workflow the request channel is the privacy intake, and
    even free-form complaints ("my old profile still appears in search") are follow-ups to an
    earlier deletion request.  A request is only non-deletion when the person explicitly asks
    for something else or says the account/records must be kept.
    """
    t = " ".join((text or "").lower().split())
    for pat in KEEP:
        if re.search(pat, t):
            return False, f"keep:{pat}"
    other = [p for p in OTHER_CUES if re.search(p, t)]
    pos = [p for p in DELETE_CUES if re.search(p, t)]
    if other and not pos:
        return False, f"other:{other[0]}"
    return True, "default-deletion" if not pos else "delete-cue"
