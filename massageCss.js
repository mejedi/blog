// Massage `hugo gen chromastyles` output to make it work with congo theme.
const css = require('css') // `npm install css`
const fs = require('fs')

const frappe = fs.readFileSync('catppuccinFrappe.css', 'utf8')
const latte = fs.readFileSync('catppuccinLatte.css', 'utf8')

function massage(style, selPrefix) {
    const ast = css.parse(style)
    const stylesheet = ast.stylesheet;

    if (stylesheet.parsingErrors.length !== 0) {
        throw new Error(stylesheet.parsingErrors)
    }

    stylesheet.rules = stylesheet.rules.filter(r => r.type === 'rule').map(r => {
        const props = {};
        for (const decl of r.declarations) props[decl.property] = decl.value;
        return {
            type: 'rule',
            selectors: r.selectors.map(sel => (selPrefix || '') + sel),
            declarations: [{ type: 'declaration', property: 'color', value: props['color'] || 'inherit'}]
        }
    })
    return css.stringify(ast, { indent: '', compress: true })
}

console.log(massage(latte))
console.log(massage(frappe, '.dark '))
