package com.example.intelfeed.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.DisableSelection
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberCyan
import com.example.intelfeed.theme.SlateDark500
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.theme.ThemeEngine
import com.example.intelfeed.ui.reader.ReaderFontSize
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.util.ArticleHtml
import com.example.intelfeed.util.Clipboard

private val BodyColor: Color
    get() = androidx.compose.ui.graphics.lerp(TextPrimary, TextSecondary, 0.25f)

/** A highlighted entity name the reader tapped: which entity, and the phrase as written in the article. */
data class EntityMark(val type: String, val id: String, val name: String, val text: String)

/**
 * Renders parsed article blocks. Text is selectable (for copying indicators); links go through
 * [onLinkClick], which opens them via ExternalLinks.
 *
 * Marks added by ArticleLinker look like the web reader's: an entity name keeps the text colour
 * and gets a 2 dp dotted underline in its type's colour (observables are also monospace); a
 * glossary term gets a thin dotted underline in the muted text colour. An entity inside a link
 * takes the tap, as on the web (the popover opens instead of the link).
 */
@Composable
fun ArticleContent(
    blocks: List<ArticleHtml.Block>,
    fontSize: ReaderFontSize,
    onLinkClick: (String) -> Unit,
    modifier: Modifier = Modifier,
    highlightQuery: String? = null,
    // Taps on marks added by ArticleLinker.
    onEntityClick: ((EntityMark) -> Unit)? = null,
    onKeywordClick: ((String) -> Unit)? = null,
    onGlossaryClick: ((String) -> Unit)? = null
) {
    val linkHandler by rememberUpdatedState(onLinkClick)
    val entityHandler by rememberUpdatedState(onEntityClick)
    val keywordHandler by rememberUpdatedState(onKeywordClick)
    val glossaryHandler by rememberUpdatedState(onGlossaryClick)
    val handlers = remember {
        MarkHandlers(
            entity = { mark -> entityHandler?.invoke(mark) },
            keyword = { word -> keywordHandler?.invoke(word) },
            glossary = { id -> glossaryHandler?.invoke(id) },
            link = { url -> linkHandler(url) }
        )
    }
    val rendered = remember(blocks, highlightQuery, ThemeEngine.variables) {
        blocks.map { block ->
            when (block) {
                is ArticleHtml.Paragraph -> block to block.text.toMarked(highlightQuery, handlers)
                is ArticleHtml.ListItem -> block to block.text.toMarked(highlightQuery, handlers)
                is ArticleHtml.Code -> block to
                    if (block.marks.isEmpty()) null else ArticleHtml.RichText(block.text, block.marks).toMarked(null, handlers)
                else -> block to null
            }
        }
    }
    SelectionContainer(modifier = modifier) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            rendered.forEach { (block, marked) ->
                when (block) {
                    is ArticleHtml.Paragraph -> ParagraphBlock(block.kind, marked!!, fontSize)
                    is ArticleHtml.ListItem -> Row(Modifier.padding(start = (12 * (block.depth - 1)).dp)) {
                        Text(
                            text = block.marker,
                            fontSize = fontSize.size,
                            lineHeight = fontSize.lineHeight,
                            color = TextMuted,
                            modifier = Modifier.widthIn(min = 22.dp)
                        )
                        MarkedText(marked!!, fontSize = fontSize.size, lineHeight = fontSize.lineHeight, color = BodyColor)
                    }
                    is ArticleHtml.Code -> CodeBlock(block.text, marked = marked)
                    is ArticleHtml.Image -> AsyncImage(
                        model = block.url,
                        contentDescription = block.alt,
                        contentScale = ContentScale.FillWidth,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 420.dp)
                            .clip(RoundedCornerShape(8.dp))
                    )
                    ArticleHtml.Divider -> HorizontalDivider(color = SlateDark700)
                }
            }
        }
    }
}

@Composable
private fun ParagraphBlock(kind: ArticleHtml.TextKind, text: MarkedString, fontSize: ReaderFontSize) {
    when (kind) {
        ArticleHtml.TextKind.H1 -> MarkedText(text, fontSize = fontSize.size * 1.4f, lineHeight = fontSize.lineHeight * 1.3f, fontWeight = FontWeight.Bold, color = TextPrimary, modifier = Modifier.padding(top = 8.dp))
        ArticleHtml.TextKind.H2 -> MarkedText(text, fontSize = fontSize.size * 1.25f, lineHeight = fontSize.lineHeight * 1.2f, fontWeight = FontWeight.Bold, color = TextPrimary, modifier = Modifier.padding(top = 6.dp))
        ArticleHtml.TextKind.H3 -> MarkedText(text, fontSize = fontSize.size * 1.1f, lineHeight = fontSize.lineHeight * 1.1f, fontWeight = FontWeight.SemiBold, color = TextPrimary, modifier = Modifier.padding(top = 4.dp))
        ArticleHtml.TextKind.QUOTE -> Row(Modifier.fillMaxWidth()) {
            Box(Modifier.width(3.dp).heightIn(min = 20.dp).background(CyberBlue.copy(alpha = 0.6f), RoundedCornerShape(2.dp)))
            Spacer(Modifier.width(12.dp))
            MarkedText(text, fontSize = fontSize.size, lineHeight = fontSize.lineHeight, fontStyle = FontStyle.Italic, color = TextSecondary)
        }
        ArticleHtml.TextKind.CAPTION -> MarkedText(text, fontSize = fontSize.size * 0.85f, lineHeight = fontSize.lineHeight * 0.85f, color = TextMuted)
        ArticleHtml.TextKind.BODY -> MarkedText(text, fontSize = fontSize.size, lineHeight = fontSize.lineHeight, color = BodyColor)
    }
}

@Composable
fun CodeBlock(code: String, modifier: Modifier = Modifier, marked: MarkedString? = null) {
    val context = LocalContext.current
    Surface(
        color = SlateDark800,
        shape = RoundedCornerShape(8.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, SlateDark700),
        modifier = modifier.fillMaxWidth()
    ) {
        Box {
            MarkedText(
                text = marked ?: MarkedString(AnnotatedString(code), emptyList()),
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                lineHeight = 19.sp,
                color = CyberCyan,
                softWrap = false,
                modifier = Modifier
                    .horizontalScroll(rememberScrollState())
                    .padding(start = 14.dp, end = 48.dp, top = 14.dp, bottom = 14.dp)
            )
            DisableSelection {
                IconButton(
                    onClick = { Clipboard.copy(context, "Code", code) },
                    modifier = Modifier.align(Alignment.TopEnd)
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy code", tint = TextMuted, modifier = Modifier.size(18.dp))
                }
            }
        }
    }
}

/** Text plus the dotted underlines drawn under its entity and glossary marks. */
class MarkedString(val text: AnnotatedString, val underlines: List<Underline>)

/** [thick]: the entity style (2 dp, below the descenders); otherwise the glossary style (1 dp). */
class Underline(val start: Int, val end: Int, val color: Color, val thick: Boolean)

// The web's --text-muted, used for the glossary underline.
private val GlossaryUnderline: Color
    get() = SlateDark500


/** Text that draws [MarkedString.underlines] behind itself once it's laid out. */
@Composable
private fun MarkedText(
    text: MarkedString,
    fontSize: TextUnit,
    lineHeight: TextUnit,
    color: Color,
    modifier: Modifier = Modifier,
    fontWeight: FontWeight? = null,
    fontStyle: FontStyle? = null,
    fontFamily: FontFamily? = null,
    softWrap: Boolean = true
) {
    if (text.underlines.isEmpty()) {
        Text(text.text, fontSize = fontSize, lineHeight = lineHeight, color = color, fontWeight = fontWeight, fontStyle = fontStyle, fontFamily = fontFamily, softWrap = softWrap, modifier = modifier)
        return
    }
    var layout by remember { mutableStateOf<TextLayoutResult?>(null) }
    Text(
        text.text,
        fontSize = fontSize,
        lineHeight = lineHeight,
        color = color,
        fontWeight = fontWeight,
        fontStyle = fontStyle,
        fontFamily = fontFamily,
        softWrap = softWrap,
        onTextLayout = { layout = it },
        modifier = modifier.drawBehind {
            val l = layout ?: return@drawBehind
            if (l.layoutInput.text.text != text.text.text) return@drawBehind
            drawUnderlines(l, text.underlines, fontSize)
        }
    )
}

private fun DrawScope.drawUnderlines(layout: TextLayoutResult, underlines: List<Underline>, fontSize: TextUnit) {
    val length = layout.layoutInput.text.length
    val em = if (fontSize.isSp) fontSize.toPx() else 16.sp.toPx()
    for (u in underlines) {
        val start = u.start.coerceIn(0, length)
        val end = u.end.coerceIn(0, length)
        if (end <= start) continue
        // Entity: CSS `border-bottom: 2px dotted` under the inline box (descent + 1px padding).
        // Glossary: `text-decoration: underline dotted` offset 3px, about 1px thick.
        val stroke = if (u.thick) 2.dp.toPx() else 1.dp.toPx()
        val drop = if (u.thick) em * 0.24f + 2.dp.toPx() else em * 0.1f + 3.dp.toPx()
        val effect = PathEffect.dashPathEffect(floatArrayOf(0.01f, stroke * 2), 0f)
        for (line in layout.getLineForOffset(start)..layout.getLineForOffset(end - 1)) {
            val s = maxOf(start, layout.getLineStart(line))
            val e = minOf(end, layout.getLineEnd(line, visibleEnd = true))
            if (e <= s) continue
            val first = layout.getBoundingBox(s)
            val last = layout.getBoundingBox(e - 1)
            val left = minOf(first.left, last.left)
            val right = maxOf(first.right, last.right)
            val y = layout.getLineBaseline(line) + drop
            drawLine(u.color, Offset(left + stroke / 2, y), Offset(right - stroke / 2, y), strokeWidth = stroke, cap = StrokeCap.Round, pathEffect = effect)
        }
    }
}

private class MarkHandlers(
    val entity: (EntityMark) -> Unit,
    val keyword: (String) -> Unit,
    val glossary: (String) -> Unit,
    val link: (String) -> Unit
)

private fun ArticleHtml.RichText.toMarked(highlightQuery: String?, marks: MarkHandlers): MarkedString {
    val underlines = mutableListOf<Underline>()
    // Entities take taps inside links (the web opens the popover, not the link).
    val entityRanges = spans.filter { it.kind == ArticleHtml.SpanKind.ENTITY && it.entityType != null && it.entityId != null }
        .map { it.start until it.end }
    val annotated = buildAnnotatedString {
        append(text)
        for (span in spans) {
            when (span.kind) {
                ArticleHtml.SpanKind.BOLD -> addStyle(SpanStyle(fontWeight = FontWeight.Bold, color = TextPrimary), span.start, span.end)
                ArticleHtml.SpanKind.ITALIC -> addStyle(SpanStyle(fontStyle = FontStyle.Italic), span.start, span.end)
                ArticleHtml.SpanKind.CODE -> addStyle(
                    SpanStyle(fontFamily = FontFamily.Monospace, background = SlateDark800, color = CyberCyan),
                    span.start, span.end
                )
                ArticleHtml.SpanKind.STRIKE -> addStyle(SpanStyle(textDecoration = TextDecoration.LineThrough), span.start, span.end)
                ArticleHtml.SpanKind.UNDERLINE -> addStyle(SpanStyle(textDecoration = TextDecoration.Underline), span.start, span.end)
                ArticleHtml.SpanKind.MARK -> addStyle(SpanStyle(background = CyberAmber.copy(alpha = 0.3f)), span.start, span.end)
                ArticleHtml.SpanKind.ENTITY -> {
                    val type = span.entityType
                    val id = span.entityId
                    val entityType = EntityType.fromKey(type)
                    // The web falls back to the CVE colour for an entity it can't type.
                    val color = entityType?.color() ?: EntityType.CVE.color()
                    underlines += Underline(span.start, span.end, color, thick = true)
                    val style = if (entityType == EntityType.OBSERVABLE) SpanStyle(fontFamily = FontFamily.Monospace, fontSize = 0.94.em) else SpanStyle()
                    if (type != null && id != null) {
                        val phrase = text.substring(span.start, span.end)
                        val mark = EntityMark(type, id, span.entityName ?: phrase, phrase)
                        addLink(
                            LinkAnnotation.Clickable(
                                "entity:$type:$id",
                                TextLinkStyles(style = style, pressedStyle = SpanStyle(background = color.copy(alpha = 0.18f)))
                            ) { marks.entity(mark) },
                            span.start, span.end
                        )
                    } else {
                        addStyle(style, span.start, span.end)
                    }
                }
                ArticleHtml.SpanKind.GLOSSARY -> {
                    underlines += Underline(span.start, span.end, GlossaryUnderline, thick = false)
                    val id = span.glossaryId
                    // Inside a link the link keeps the tap, as a click does on the web.
                    val inLink = spans.any { it.kind == ArticleHtml.SpanKind.LINK && it.start < span.end && it.end > span.start }
                    if (id != null && !inLink) {
                        addLink(
                            LinkAnnotation.Clickable(
                                "glossary:$id",
                                TextLinkStyles(pressedStyle = SpanStyle(background = SlateDark700))
                            ) { marks.glossary(id) },
                            span.start, span.end
                        )
                    }
                }
                ArticleHtml.SpanKind.KEYWORD -> {
                    val word = text.substring(span.start, span.end)
                    val style = SpanStyle(background = CyberAmber.copy(alpha = 0.3f), color = TextPrimary, fontWeight = FontWeight.SemiBold)
                    addLink(LinkAnnotation.Clickable("keyword:$word", TextLinkStyles(style)) { marks.keyword(word) }, span.start, span.end)
                }
                ArticleHtml.SpanKind.LINK -> {
                    val url = span.url ?: continue
                    val linkStyle = TextLinkStyles(SpanStyle(color = CyberBlue, textDecoration = TextDecoration.Underline))
                    // The parts of the link not covered by an entity name.
                    var at = span.start
                    for (r in entityRanges.filter { it.first < span.end && it.last + 1 > span.start }.sortedBy { it.first }) {
                        if (r.first > at) addLink(LinkAnnotation.Clickable(url, linkStyle) { marks.link(url) }, at, r.first)
                        addStyle(linkStyle.style!!, maxOf(r.first, span.start), minOf(r.last + 1, span.end))
                        at = maxOf(at, r.last + 1)
                    }
                    if (at < span.end) addLink(LinkAnnotation.Clickable(url, linkStyle) { marks.link(url) }, at, span.end)
                }
            }
        }
        if (!highlightQuery.isNullOrBlank()) {
            val q = highlightQuery.trim()
            if (q.isNotEmpty()) {
                var index = text.indexOf(q, ignoreCase = true)
                while (index >= 0) {
                    val end = (index + q.length).coerceAtMost(text.length)
                    addStyle(
                        SpanStyle(background = CyberAmber, color = Color.Black, fontWeight = FontWeight.Bold),
                        index, end
                    )
                    val nextStart = index + q.length
                    if (nextStart >= text.length) break
                    index = text.indexOf(q, nextStart, ignoreCase = true)
                }
            }
        }
    }
    return MarkedString(annotated, underlines)
}
